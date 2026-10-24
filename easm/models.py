"""Core data models for the EASM pipeline.

Plain dataclasses are used (no pydantic dependency) to keep the runtime
image small and cheap to build. Everything serializes to plain dicts so the
results can be handed to the LLM or written to JSON cheaply.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    NETBLOCK = "netblock"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# How an asset was discovered. Used for attribution scoring: some sources
# are stronger evidence of ownership than others.
class DiscoveryMethod(str, Enum):
    SEED = "seed"                 # provided directly by the user (authoritative)
    CT_LOG = "ct_log"             # certificate transparency logs
    DNS = "dns"                   # resolved from a known host
    TLS_SAN = "tls_san"           # found in a cert's Subject Alternative Names
    RDAP = "rdap"                 # ownership/registration pivot
    ASN = "asn"                   # same autonomous system / netblock
    REVERSE_WHOIS = "reverse_whois"
    ENRICHMENT = "enrichment"     # Shodan/Censys etc.


@dataclass
class Asset:
    """A single discovered asset (hostname, IP, or netblock)."""

    value: str
    asset_type: AssetType
    # Which seed(s) this asset traces back to. More independent seeds =>
    # higher confidence it belongs to the organization.
    discovered_from: set[str] = field(default_factory=set)
    # Which methods surfaced this asset.
    methods: set[DiscoveryMethod] = field(default_factory=set)
    # Depth in the recursive expansion (0 = seed). Bounds cost/termination.
    depth: int = 0
    # Resolved data populated during enrichment.
    ip_addresses: set[str] = field(default_factory=set)
    cnames: list[str] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    # 0.0 - 1.0, filled in by the attribution module.
    confidence: float = 0.0
    attributes: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "Asset") -> None:
        """Fold another record for the same asset into this one."""
        self.discovered_from |= other.discovered_from
        self.methods |= other.methods
        self.ip_addresses |= other.ip_addresses
        self.ports |= other.ports
        self.depth = min(self.depth, other.depth)
        for c in other.cnames:
            if c not in self.cnames:
                self.cnames.append(c)
        self.attributes.update(other.attributes)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["asset_type"] = self.asset_type.value
        d["discovered_from"] = sorted(self.discovered_from)
        d["methods"] = sorted(m.value for m in self.methods)
        d["ip_addresses"] = sorted(self.ip_addresses)
        d["ports"] = sorted(self.ports)
        return d


@dataclass
class Finding:
    """A potential exposure / risk associated with an asset."""

    asset: str
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Full output of a scan: inventory + findings + metadata."""

    seeds: list[str]
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seeds": self.seeds,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": self.stats,
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.findings],
        }
