"""Scan orchestration.

Runs the recursive multi-seed discovery pipeline and produces a ScanResult:

    seeds -> CT logs -> candidate subdomains
          -> DNS resolve -> IPs (+ dangling CNAME detection)
          -> TLS inspect -> SANs (feed back) + cert findings
          -> HTTP inspect -> exposure findings
          -> RDAP (seeds + a sample of IPs) -> ownership / netblock signal
          -> optional enrichment (Shodan/Censys) -> ports/services
          -> merge + dedup -> attribution scoring -> findings

Everything is bounded by max_depth, max_assets, concurrency and per-request
timeouts so a scan terminates quickly and stays cheap. Network failures in any
single source are swallowed; the scan continues with whatever data it gathered.
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timezone

import httpx

from . import attribution, findings
from .config import ScanConfig
from .discovery import ct_logs, dns, http, rdap, tls
from .enrich import scanners
from .models import (
    Asset,
    AssetType,
    DiscoveryMethod,
    Finding,
    ScanResult,
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class Scanner:
    def __init__(self, config: ScanConfig):
        self.cfg = config
        self.opts = config.options
        self.sem = asyncio.Semaphore(self.opts.concurrency)
        # value(lower) -> Asset
        self.assets: dict[str, Asset] = {}
        self.findings: list[Finding] = []
        self.stats: dict[str, int] = {}

    # --- asset bookkeeping -------------------------------------------------
    def _add(
        self,
        value: str,
        atype: AssetType,
        method: DiscoveryMethod,
        seed: str,
        depth: int,
    ) -> Asset | None:
        value = value.lower().rstrip(".")
        if not value:
            return None
        key = value
        existing = self.assets.get(key)
        if existing:
            existing.discovered_from.add(seed)
            existing.methods.add(method)
            existing.depth = min(existing.depth, depth)
            return existing
        if len(self.assets) >= self.opts.max_assets:
            return None
        asset = Asset(
            value=value,
            asset_type=atype,
            discovered_from={seed},
            methods={method},
            depth=depth,
        )
        self.assets[key] = asset
        return asset

    async def _guard(self, coro):
        async with self.sem:
            return await coro

    # --- main entry --------------------------------------------------------
    async def run(self) -> ScanResult:
        result = ScanResult(seeds=list(self.cfg.seeds.domains))

        # 1. Seed the inventory with the authoritative inputs.
        for d in self.cfg.seeds.domains:
            atype = AssetType.IP if _is_ip(d) else AssetType.DOMAIN
            self._add(d, atype, DiscoveryMethod.SEED, seed=d, depth=0)
        for cidr in self.cfg.seeds.ip_ranges:
            self._add(cidr, AssetType.NETBLOCK, DiscoveryMethod.SEED, seed=cidr, depth=0)

        async with httpx.AsyncClient(
            timeout=self.opts.timeout, follow_redirects=True, verify=False
        ) as client:
            # 2. Per-seed CT-log subdomain discovery (biggest source).
            await self._discover_ct(client)

            # 3. Recursive resolve + TLS SAN expansion up to max_depth.
            await self._expand(client)

            # 4. HTTP inspection for exposure findings.
            if self.opts.inspect_http:
                await self._inspect_http(client)

            # 5. Ownership / netblock signal via RDAP on seeds + sampled IPs.
            await self._rdap(client)

        # 6. Optional enrichment (own client / rate limits inside).
        await self._enrich()

        # 7. Merge, score, finalize.
        assets = attribution.score_all(
            list(self.assets.values()), total_seeds=len(self.cfg.seeds.domains)
        )
        result.assets = assets
        result.findings = _dedup_findings(self.findings)
        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.stats = {
            "total_assets": len(assets),
            "in_scope_assets": sum(1 for a in assets if attribution.in_scope(a)),
            "total_findings": len(result.findings),
            **self.stats,
        }
        return result

    # --- stages ------------------------------------------------------------
    async def _discover_ct(self, client: httpx.AsyncClient) -> None:
        domains = [a for a in list(self.assets.values())
                   if a.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
                   and a.depth == 0]

        async def one(seed_asset: Asset):
            subs = await ct_logs.discover_subdomains(
                seed_asset.value, timeout=self.opts.timeout, client=client
            )
            for host in subs:
                atype = AssetType.DOMAIN if host == seed_asset.value else AssetType.SUBDOMAIN
                self._add(host, atype, DiscoveryMethod.CT_LOG,
                          seed=seed_asset.value, depth=1)

        await asyncio.gather(*(self._guard(one(a)) for a in domains))
        self.stats["ct_hosts"] = sum(
            1 for a in self.assets.values() if DiscoveryMethod.CT_LOG in a.methods
        )

    async def _expand(self, client: httpx.AsyncClient) -> None:
        """Resolve hosts and expand via TLS SANs, breadth-first up to max_depth."""
        for depth in range(0, self.opts.max_depth + 1):
            hosts = [
                a for a in list(self.assets.values())
                if a.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
                and a.depth <= depth
                and "resolved" not in a.attributes
            ]
            if not hosts:
                continue

            async def process(asset: Asset):
                asset.attributes["resolved"] = True
                full = asset.depth == 0  # seeds get MX/NS/TXT too
                rec = await dns.resolve(
                    asset.value, timeout=self.opts.timeout, full=full
                )
                asset.ip_addresses |= rec.ips
                asset.cnames = rec.cname
                # Register discovered IPs as assets.
                for ip in rec.ips:
                    self._add(ip, AssetType.IP, DiscoveryMethod.DNS,
                              seed=next(iter(asset.discovered_from)),
                              depth=min(asset.depth + 1, self.opts.max_depth))
                self.findings.extend(findings.from_dns(rec))

                # TLS inspection + SAN expansion (only if resolvable & enabled).
                if self.opts.inspect_tls and rec.resolves:
                    info = await tls.inspect(asset.value, timeout=self.opts.timeout)
                    if info.connected:
                        asset.attributes["tls_issuer"] = info.issuer
                        self.findings.extend(findings.from_tls(info))
                        if asset.depth + 1 <= self.opts.max_depth:
                            for san in info.sans:
                                self._add(
                                    san, AssetType.SUBDOMAIN,
                                    DiscoveryMethod.TLS_SAN,
                                    seed=next(iter(asset.discovered_from)),
                                    depth=asset.depth + 1,
                                )

            await asyncio.gather(*(self._guard(process(a)) for a in hosts))

    async def _inspect_http(self, client: httpx.AsyncClient) -> None:
        hosts = [
            a for a in list(self.assets.values())
            if a.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            and a.ip_addresses
        ]

        async def one(asset: Asset):
            info = await http.inspect(asset.value, timeout=self.opts.timeout, client=client)
            if info.reachable:
                asset.attributes["http_status"] = info.status
                asset.attributes["http_server"] = info.server
                self.findings.extend(findings.from_http(info))

        await asyncio.gather(*(self._guard(one(a)) for a in hosts))

    async def _rdap(self, client: httpx.AsyncClient) -> None:
        # Domain registration for each seed (ownership baseline).
        seed_domains = [
            a for a in self.assets.values()
            if a.depth == 0 and a.asset_type == AssetType.DOMAIN
        ]
        orgs: set[str] = {o.lower() for o in self.cfg.seeds.org_names}

        async def dom(asset: Asset):
            reg = await rdap.lookup_domain(asset.value, timeout=self.opts.timeout, client=client)
            if reg.raw_ok:
                if reg.org:
                    asset.attributes["registrant_org"] = reg.org
                    orgs.add(reg.org.lower())
                if reg.expires:
                    asset.attributes["domain_expires"] = reg.expires

        await asyncio.gather(*(self._guard(dom(a)) for a in seed_domains))

        # Sample a bounded number of unique IPs for netblock attribution.
        ips = [a for a in self.assets.values() if a.asset_type == AssetType.IP][:50]

        async def ipn(asset: Asset):
            net = await rdap.lookup_ip(asset.value, timeout=self.opts.timeout, client=client)
            if net.raw_ok:
                if net.cidr:
                    asset.attributes["netblock"] = net.cidr
                    nb = self._add(net.cidr, AssetType.NETBLOCK, DiscoveryMethod.ASN,
                                   seed=next(iter(asset.discovered_from)),
                                   depth=asset.depth)
                    if nb and net.org:
                        nb.attributes["org"] = net.org
                if net.org:
                    asset.attributes["ip_org"] = net.org
                    # Corroborate ownership if the netblock org matches a seed org.
                    if any(o in net.org.lower() or net.org.lower() in o for o in orgs if o):
                        asset.methods.add(DiscoveryMethod.RDAP)

        await asyncio.gather(*(self._guard(ipn(a)) for a in ips))

    async def _enrich(self) -> None:
        if not (self.opts.enrichment.shodan or self.opts.enrichment.censys):
            return
        ip_assets = [a for a in self.assets.values() if a.asset_type == AssetType.IP]
        ips = [a.value for a in ip_assets]
        if not ips:
            return
        intel = await scanners.enrich_ips(ips, self.opts.enrichment, timeout=self.opts.timeout)
        for asset in ip_assets:
            hi = intel.get(asset.value)
            if not hi:
                continue
            asset.ports |= hi.ports
            asset.methods.add(DiscoveryMethod.ENRICHMENT)
            if hi.services:
                asset.attributes["services"] = hi.services
            self.findings.extend(findings.exposed_port_findings(asset.value, hi.ports))
        self.stats["enriched_ips"] = len(intel)


def _dedup_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in items:
        key = (f.asset, f.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: sev_order.get(f.severity.value, 9))
    return out


async def run_scan(config: ScanConfig) -> ScanResult:
    """Convenience coroutine used by the agent and the local harness."""
    return await Scanner(config).run()
