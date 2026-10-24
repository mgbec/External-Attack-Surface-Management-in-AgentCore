"""Configuration models and loading for a scan.

A scan is driven entirely by a small JSON config: the seed set plus a few
options. Everything has a cheap, safe default so a minimal config is just a
list of domains.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Seeds:
    domains: list[str] = field(default_factory=list)
    org_names: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)


@dataclass
class EnrichmentOptions:
    # Off by default: these can hit paid API quotas. Keys pulled from env.
    shodan: bool = False
    censys: bool = False
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None


@dataclass
class ScanOptions:
    # Recursion depth for subdomain/SAN expansion. 2 keeps scans fast + cheap.
    max_depth: int = 2
    # "off" | "flag_only" | "expand". flag_only reports sibling domains found
    # via reverse-WHOIS but does not recurse into them (tighter scope, cheap).
    reverse_whois: str = "flag_only"
    # Cap total assets processed to bound cost on large orgs.
    max_assets: int = 2000
    # Per-request network timeout (seconds).
    timeout: float = 8.0
    # Max concurrent network operations.
    concurrency: int = 20
    # Light-active inspection (normal HTTP/TLS to discovered hosts). These are
    # ordinary web requests; safe for assets you own or are authorized to test.
    inspect_http: bool = True
    inspect_tls: bool = True
    enrichment: EnrichmentOptions = field(default_factory=EnrichmentOptions)

    # Bedrock model used for triage/reporting. Default is a cheap small model.
    model_id: str = "us.anthropic.claude-3-5-haiku-20241022-v1:0"


@dataclass
class ScanConfig:
    seeds: Seeds
    options: ScanOptions = field(default_factory=ScanOptions)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        raw_seeds = data.get("seeds", {})
        # Allow a bare list of domains as shorthand.
        if isinstance(raw_seeds, list):
            raw_seeds = {"domains": raw_seeds}
        seeds = Seeds(
            domains=[_norm_domain(d) for d in raw_seeds.get("domains", [])],
            org_names=list(raw_seeds.get("org_names", [])),
            ip_ranges=list(raw_seeds.get("ip_ranges", [])),
        )

        raw_opts = data.get("options", {}) or {}
        raw_enrich = raw_opts.get("enrichment", {}) or {}
        enrich = EnrichmentOptions(
            shodan=bool(raw_enrich.get("shodan", False)),
            censys=bool(raw_enrich.get("censys", False)),
            # Keys come from env by default so they never live in config files.
            shodan_api_key=raw_enrich.get("shodan_api_key") or os.getenv("SHODAN_API_KEY"),
            censys_api_id=raw_enrich.get("censys_api_id") or os.getenv("CENSYS_API_ID"),
            censys_api_secret=raw_enrich.get("censys_api_secret") or os.getenv("CENSYS_API_SECRET"),
        )
        opts = ScanOptions(
            max_depth=int(raw_opts.get("max_depth", 2)),
            reverse_whois=str(raw_opts.get("reverse_whois", "flag_only")),
            max_assets=int(raw_opts.get("max_assets", 2000)),
            timeout=float(raw_opts.get("timeout", 8.0)),
            concurrency=int(raw_opts.get("concurrency", 20)),
            inspect_http=bool(raw_opts.get("inspect_http", True)),
            inspect_tls=bool(raw_opts.get("inspect_tls", True)),
            enrichment=enrich,
            model_id=str(raw_opts.get("model_id", ScanOptions.model_id)),
        )
        return cls(seeds=seeds, options=opts)

    @classmethod
    def from_json_file(cls, path: str) -> "ScanConfig":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def _norm_domain(domain: str) -> str:
    """Normalize a domain: strip scheme, path, whitespace, trailing dot, lowercase."""
    d = domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]  # strip port
    return d.rstrip(".")
