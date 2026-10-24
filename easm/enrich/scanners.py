"""Shodan / Censys enrichment for discovered IPs.

Both are optional. Each returns a mapping of ip -> {ports, services, raw} and
never raises: a missing key, missing library, or quota error degrades to an
empty result so the free discovery core is unaffected.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from ..config import EnrichmentOptions


@dataclass
class HostIntel:
    ip: str
    ports: set[int] = field(default_factory=set)
    services: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = ""


async def enrich_ips(
    ips: list[str], opts: EnrichmentOptions, *, timeout: float = 8.0
) -> dict[str, HostIntel]:
    """Dispatch to whichever enrichment sources are enabled + configured."""
    results: dict[str, HostIntel] = {}
    if opts.shodan and opts.shodan_api_key:
        _merge(results, await _shodan(ips, opts.shodan_api_key, timeout))
    if opts.censys and opts.censys_api_id and opts.censys_api_secret:
        _merge(
            results,
            await _censys(ips, opts.censys_api_id, opts.censys_api_secret, timeout),
        )
    return results


def _merge(into: dict[str, HostIntel], new: dict[str, HostIntel]) -> None:
    for ip, intel in new.items():
        if ip in into:
            into[ip].ports |= intel.ports
            into[ip].services.extend(intel.services)
            into[ip].tags.extend(intel.tags)
        else:
            into[ip] = intel


async def _shodan(
    ips: list[str], api_key: str, timeout: float
) -> dict[str, HostIntel]:
    """Use Shodan's free host lookup REST endpoint (no SDK dependency)."""
    out: dict[str, HostIntel] = {}
    url = "https://api.shodan.io/shodan/host/{ip}"
    async with httpx.AsyncClient(timeout=timeout) as client:

        async def one(ip: str):
            try:
                resp = await client.get(
                    url.format(ip=ip), params={"key": api_key, "minify": "true"}
                )
                if resp.status_code != 200:
                    return
                data = resp.json()
                out[ip] = HostIntel(
                    ip=ip,
                    ports=set(data.get("ports", []) or []),
                    tags=list(data.get("tags", []) or []),
                    services=[str(data.get("os") or "")] if data.get("os") else [],
                    source="shodan",
                )
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
                return

        # Keep concurrency low to respect free-tier rate limits.
        sem = asyncio.Semaphore(2)

        async def guarded(ip):
            async with sem:
                await one(ip)

        await asyncio.gather(*(guarded(ip) for ip in ips))
    return out


async def _censys(
    ips: list[str], api_id: str, api_secret: str, timeout: float
) -> dict[str, HostIntel]:
    """Censys Platform host view via its REST API using basic auth."""
    out: dict[str, HostIntel] = {}
    base = "https://search.censys.io/api/v2/hosts/{ip}"
    auth = (api_id, api_secret)
    async with httpx.AsyncClient(timeout=timeout, auth=auth) as client:

        async def one(ip: str):
            try:
                resp = await client.get(base.format(ip=ip))
                if resp.status_code != 200:
                    return
                result = resp.json().get("result", {})
                svcs = result.get("services", []) or []
                out[ip] = HostIntel(
                    ip=ip,
                    ports={s.get("port") for s in svcs if s.get("port")},
                    services=[
                        f"{s.get('service_name')}/{s.get('port')}" for s in svcs
                    ],
                    source="censys",
                )
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
                return

        sem = asyncio.Semaphore(2)

        async def guarded(ip):
            async with sem:
                await one(ip)

        await asyncio.gather(*(guarded(ip) for ip in ips))
    return out
