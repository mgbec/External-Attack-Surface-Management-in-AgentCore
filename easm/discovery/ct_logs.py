"""Certificate Transparency log discovery via crt.sh.

CT logs are public, append-only records of every TLS certificate issued by
participating CAs. Because certs enumerate the hostnames they cover, mining
them is the single most productive passive source of subdomains - including
hosts that are not linked from anywhere.

crt.sh exposes a free JSON endpoint; no API key required.
"""

from __future__ import annotations

import asyncio

import httpx

CRTSH_URL = "https://crt.sh/"


async def discover_subdomains(
    domain: str,
    *,
    timeout: float = 8.0,
    client: httpx.AsyncClient | None = None,
) -> set[str]:
    """Return the set of hostnames crt.sh has seen certificates for under `domain`.

    Never raises on network/parse errors - discovery is best-effort, and a
    single failed source should not abort a scan.
    """
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    found: set[str] = set()
    try:
        # %25 is a URL-encoded '%' wildcard => match *.domain and domain.
        resp = await client.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "easm-agentcore/0.1 (+passive-recon)"},
        )
        if resp.status_code != 200:
            return found
        # crt.sh occasionally returns concatenated JSON; the json output mode
        # returns a proper array, but guard anyway.
        try:
            rows = resp.json()
        except ValueError:
            return found

        for row in rows:
            name_value = row.get("name_value", "")
            common = row.get("common_name", "")
            for raw in name_value.split("\n") + [common]:
                host = raw.strip().lower().lstrip("*.").rstrip(".")
                if not host or "@" in host:
                    continue
                # Keep only hosts within the queried domain.
                if host == domain or host.endswith("." + domain):
                    found.add(host)
    except (httpx.HTTPError, asyncio.TimeoutError):
        return found
    finally:
        if owns_client:
            await client.aclose()

    return found
