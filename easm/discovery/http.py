"""HTTP response/header inspection.

A single GET to a discovered host (ordinary web traffic) reveals exposure
signals without any intrusive probing:
  - missing security headers (HSTS, CSP, X-Frame-Options, ...)
  - server/framework banners that leak versions
  - redirect target (http->https posture)
  - status for common exposed paths is intentionally NOT probed here to keep
    traffic minimal and non-intrusive; only the root document is fetched.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


@dataclass
class HttpInfo:
    host: str
    url: str | None = None
    reachable: bool = False
    status: int | None = None
    scheme: str | None = None
    server: str | None = None
    powered_by: str | None = None
    title: str | None = None
    missing_security_headers: list[str] = field(default_factory=list)
    final_url: str | None = None
    error: str | None = None


async def inspect(
    host: str,
    *,
    timeout: float = 8.0,
    client: httpx.AsyncClient | None = None,
) -> HttpInfo:
    owns = client is None
    if owns:
        client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False
        )
    info = HttpInfo(host=host)
    # Prefer HTTPS; fall back to HTTP.
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = await client.get(
                url, headers={"User-Agent": "easm-agentcore/0.1 (+passive-recon)"}
            )
            info.reachable = True
            info.url = url
            info.scheme = scheme
            info.status = resp.status_code
            info.final_url = str(resp.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            info.server = headers.get("server")
            info.powered_by = headers.get("x-powered-by")
            info.missing_security_headers = [
                h for h in SECURITY_HEADERS if h not in headers
            ]
            info.title = _extract_title(resp.text) if resp.text else None
            break
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            info.error = type(exc).__name__
            continue
    if owns:
        await client.aclose()
    return info


def _extract_title(html: str) -> str | None:
    lo = html.lower()
    start = lo.find("<title")
    if start == -1:
        return None
    gt = lo.find(">", start)
    end = lo.find("</title>", gt)
    if gt == -1 or end == -1:
        return None
    return html[gt + 1 : end].strip()[:200] or None
