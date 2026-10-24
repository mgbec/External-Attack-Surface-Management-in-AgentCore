"""Asset merge/dedup + attribution confidence scoring.

The hard problem in EASM is not finding more assets - it is deciding which
discovered assets actually belong to the organization. With multiple seed
domains we get a strong extra signal: an asset reachable from several
independent seeds is very likely in scope.

Confidence (0.0 - 1.0) combines:
  - discovery method strength (a seed is authoritative; a shared netblock is
    weaker than a subdomain of a known domain)
  - number of independent seeds that lead to the asset
  - shallow depth (closer to a seed => more likely in scope)
"""

from __future__ import annotations

from .models import Asset, DiscoveryMethod

# Base confidence contributed by the strongest method that found an asset.
_METHOD_WEIGHT = {
    DiscoveryMethod.SEED: 1.0,
    DiscoveryMethod.CT_LOG: 0.85,       # cert issued for the org's domain
    DiscoveryMethod.DNS: 0.8,           # resolved from a known host
    DiscoveryMethod.TLS_SAN: 0.75,      # named in the org's cert
    DiscoveryMethod.RDAP: 0.6,          # registration pivot
    DiscoveryMethod.ASN: 0.45,          # shared netblock - could be a neighbor
    DiscoveryMethod.REVERSE_WHOIS: 0.5,
    DiscoveryMethod.ENRICHMENT: 0.3,
}


def merge_assets(assets: list[Asset]) -> list[Asset]:
    """Collapse duplicate assets (same value) into one, unioning their sources."""
    by_value: dict[str, Asset] = {}
    for a in assets:
        key = a.value.lower()
        if key in by_value:
            by_value[key].merge(a)
        else:
            by_value[key] = a
    return list(by_value.values())


def score(asset: Asset, total_seeds: int) -> float:
    """Compute and store a 0-1 confidence that `asset` belongs to the org."""
    if not asset.methods:
        asset.confidence = 0.0
        return 0.0

    base = max(_METHOD_WEIGHT.get(m, 0.3) for m in asset.methods)

    # Multi-seed corroboration: each extra independent seed adds evidence,
    # with diminishing returns, capped so a single strong method still scores
    # well on its own.
    n_seeds = max(1, len(asset.discovered_from))
    corroboration = min(0.15 * (n_seeds - 1), 0.3)

    # Depth penalty: assets far from any seed are more speculative.
    depth_penalty = min(0.1 * asset.depth, 0.3)

    conf = base + corroboration - depth_penalty
    conf = max(0.0, min(1.0, conf))
    asset.confidence = round(conf, 3)
    return asset.confidence


def score_all(assets: list[Asset], total_seeds: int) -> list[Asset]:
    for a in assets:
        score(a, total_seeds)
    # Highest-confidence assets first for reporting + token budgeting.
    return sorted(assets, key=lambda x: x.confidence, reverse=True)


def in_scope(asset: Asset, threshold: float = 0.5) -> bool:
    """Whether an asset is confident enough to treat as in-scope automatically.

    Assets below the threshold are still reported, but flagged for human review
    rather than asserted as the organization's."""
    return asset.confidence >= threshold
