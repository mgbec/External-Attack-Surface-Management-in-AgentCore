"""DNS resolution. Standard DNS queries are ordinary, expected traffic.

Resolving discovered hostnames turns names into IP addresses (new assets) and
surfaces CNAME chains. A CNAME pointing at a resource that no longer resolves
is a classic subdomain-takeover signal, captured here for the findings module.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.resolver


@dataclass
class DnsRecords:
    host: str
    a: list[str] = field(default_factory=list)       # IPv4
    aaaa: list[str] = field(default_factory=list)     # IPv6
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    # True when the host has a CNAME but no resolvable address => dangling.
    dangling_cname: bool = False
    resolves: bool = False

    @property
    def ips(self) -> set[str]:
        return set(self.a) | set(self.aaaa)


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


async def _query(resolver, host: str, rtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(host, rtype)
        return [r.to_text().strip('"') for r in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            asyncio.TimeoutError, dns.resolver.LifetimeTimeout):
        return []
    except Exception:
        return []


async def resolve(host: str, *, timeout: float = 8.0, full: bool = False) -> DnsRecords:
    """Resolve a host. When full=True, also fetch MX/NS/TXT (useful for seeds)."""
    resolver = _resolver(timeout)
    rec = DnsRecords(host=host)

    a, aaaa, cname = await asyncio.gather(
        _query(resolver, host, "A"),
        _query(resolver, host, "AAAA"),
        _query(resolver, host, "CNAME"),
    )
    rec.a, rec.aaaa, rec.cname = a, aaaa, [c.rstrip(".") for c in cname]

    if full:
        mx, ns, txt = await asyncio.gather(
            _query(resolver, host, "MX"),
            _query(resolver, host, "NS"),
            _query(resolver, host, "TXT"),
        )
        rec.mx, rec.ns, rec.txt = mx, ns, txt

    rec.resolves = bool(rec.a or rec.aaaa)
    # CNAME present but nothing ultimately resolves => likely dangling.
    rec.dangling_cname = bool(rec.cname) and not rec.resolves
    return rec
