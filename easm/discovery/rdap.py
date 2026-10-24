"""RDAP ownership/registration lookups + ASN/netblock pivot.

RDAP is the modern JSON replacement for WHOIS. It is free and queryable over
HTTP. Two uses here:
  1. Domain RDAP  -> registrar, registrant org, expiry (ownership signal).
  2. IP RDAP      -> the netblock (CIDR) and the owning org/handle, so an IP
                     can pivot to the whole block it belongs to.

Netblock/ASN attribution is a strong ownership signal: if several seeds land
inside the same registered block, that block is very likely the org's.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

# IANA bootstrap-backed public RDAP front doors (no key required).
DOMAIN_RDAP = "https://rdap.org/domain/"
IP_RDAP = "https://rdap.org/ip/"


@dataclass
class DomainRegistration:
    domain: str
    registrar: str | None = None
    org: str | None = None
    emails: list[str] = field(default_factory=list)
    expires: str | None = None
    raw_ok: bool = False


@dataclass
class IpNetwork:
    ip: str
    cidr: str | None = None
    name: str | None = None
    org: str | None = None
    country: str | None = None
    raw_ok: bool = False


async def lookup_domain(
    domain: str, *, timeout: float = 8.0, client: httpx.AsyncClient | None = None
) -> DomainRegistration:
    owns = client is None
    if owns:
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    reg = DomainRegistration(domain=domain)
    try:
        resp = await client.get(DOMAIN_RDAP + domain)
        if resp.status_code != 200:
            return reg
        data = resp.json()
        reg.raw_ok = True
        for ev in data.get("events", []):
            if ev.get("eventAction") == "expiration":
                reg.expires = ev.get("eventDate")
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                reg.registrar = _vcard_fn(ent)
            if "registrant" in roles:
                reg.org = _vcard_org(ent) or _vcard_fn(ent)
            reg.emails.extend(_vcard_emails(ent))
    except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
        pass
    finally:
        if owns:
            await client.aclose()
    return reg


async def lookup_ip(
    ip: str, *, timeout: float = 8.0, client: httpx.AsyncClient | None = None
) -> IpNetwork:
    owns = client is None
    if owns:
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    net = IpNetwork(ip=ip)
    try:
        resp = await client.get(IP_RDAP + ip)
        if resp.status_code != 200:
            return net
        data = resp.json()
        net.raw_ok = True
        net.name = data.get("name")
        net.country = data.get("country")
        start = data.get("startAddress")
        # cidr0_cidrs is the structured CIDR representation when present.
        cidrs = data.get("cidr0_cidrs") or []
        if cidrs:
            c = cidrs[0]
            prefix = c.get("v4prefix") or c.get("v6prefix")
            length = c.get("length")
            if prefix and length is not None:
                net.cidr = f"{prefix}/{length}"
        elif start and data.get("endAddress"):
            net.cidr = f"{start}-{data['endAddress']}"
        for ent in data.get("entities", []):
            if "registrant" in ent.get("roles", []) or "administrative" in ent.get("roles", []):
                net.org = _vcard_org(ent) or _vcard_fn(ent)
                if net.org:
                    break
    except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
        pass
    finally:
        if owns:
            await client.aclose()
    return net


# --- vCard (jCard) helpers -------------------------------------------------
# RDAP embeds contact data as jCard arrays: ["vcard", [ [field, {}, type, val] ]]

def _vcard_items(entity: dict) -> list:
    vc = entity.get("vcardArray")
    if isinstance(vc, list) and len(vc) == 2 and isinstance(vc[1], list):
        return vc[1]
    return []


def _vcard_fn(entity: dict) -> str | None:
    for item in _vcard_items(entity):
        if item and item[0] == "fn":
            return item[3]
    return None


def _vcard_org(entity: dict) -> str | None:
    for item in _vcard_items(entity):
        if item and item[0] == "org":
            val = item[3]
            return val[0] if isinstance(val, list) else val
    return None


def _vcard_emails(entity: dict) -> list[str]:
    out = []
    for item in _vcard_items(entity):
        if item and item[0] == "email" and item[3]:
            out.append(str(item[3]).lower())
    return out
