"""Tests for asset merge/dedup and attribution confidence scoring."""

from easm.attribution import in_scope, merge_assets, score, score_all
from easm.models import Asset, AssetType, DiscoveryMethod


def make_asset(value, atype=AssetType.SUBDOMAIN, methods=None, seeds=None, depth=1):
    return Asset(
        value=value,
        asset_type=atype,
        discovered_from=set(seeds or ["example.com"]),
        methods=set(methods or [DiscoveryMethod.CT_LOG]),
        depth=depth,
    )


class TestMergeAssets:
    def test_duplicates_collapse_and_union_sources(self):
        a1 = make_asset("www.example.com", seeds=["example.com"],
                        methods=[DiscoveryMethod.CT_LOG])
        a2 = make_asset("www.example.com", seeds=["example.net"],
                        methods=[DiscoveryMethod.TLS_SAN])
        merged = merge_assets([a1, a2])
        assert len(merged) == 1
        asset = merged[0]
        assert asset.discovered_from == {"example.com", "example.net"}
        assert asset.methods == {DiscoveryMethod.CT_LOG, DiscoveryMethod.TLS_SAN}

    def test_merge_is_case_insensitive(self):
        a1 = make_asset("WWW.Example.com")
        a2 = make_asset("www.example.com")
        assert len(merge_assets([a1, a2])) == 1

    def test_merge_keeps_shallowest_depth(self):
        a1 = make_asset("x.example.com", depth=3)
        a2 = make_asset("x.example.com", depth=1)
        merged = merge_assets([a1, a2])
        assert merged[0].depth == 1

    def test_distinct_assets_preserved(self):
        a1 = make_asset("a.example.com")
        a2 = make_asset("b.example.com")
        assert len(merge_assets([a1, a2])) == 2


class TestScore:
    def test_seed_scores_highest(self):
        a = make_asset("example.com", atype=AssetType.DOMAIN,
                       methods=[DiscoveryMethod.SEED], depth=0)
        assert score(a, total_seeds=1) == 1.0

    def test_no_methods_is_zero(self):
        a = make_asset("x.example.com", methods=[])
        a.methods = set()
        assert score(a, total_seeds=1) == 0.0

    def test_multi_seed_corroboration_raises_confidence(self):
        single = make_asset("shared.example.com", seeds=["example.com"],
                            methods=[DiscoveryMethod.DNS], depth=1)
        multi = make_asset("shared.example.com",
                           seeds=["example.com", "example.net", "example.org"],
                           methods=[DiscoveryMethod.DNS], depth=1)
        assert score(multi, 3) > score(single, 1)

    def test_depth_penalty_lowers_confidence(self):
        shallow = make_asset("x.example.com", methods=[DiscoveryMethod.CT_LOG], depth=1)
        deep = make_asset("x.example.com", methods=[DiscoveryMethod.CT_LOG], depth=3)
        assert score(shallow, 1) > score(deep, 1)

    def test_asn_weaker_than_ct_log(self):
        asn = make_asset("1.2.3.4", atype=AssetType.IP,
                         methods=[DiscoveryMethod.ASN], depth=1)
        ct = make_asset("y.example.com", methods=[DiscoveryMethod.CT_LOG], depth=1)
        assert score(asn, 1) < score(ct, 1)

    def test_confidence_clamped_0_1(self):
        a = make_asset("x.example.com",
                       seeds=[f"s{i}.com" for i in range(10)],
                       methods=[DiscoveryMethod.SEED], depth=0)
        c = score(a, 10)
        assert 0.0 <= c <= 1.0

    def test_strongest_method_wins(self):
        # When multiple methods found the asset, the strongest sets the base.
        a = make_asset("x.example.com",
                       methods=[DiscoveryMethod.ASN, DiscoveryMethod.SEED], depth=0)
        assert score(a, 1) == 1.0


class TestScoreAllAndScope:
    def test_score_all_sorts_desc_by_confidence(self):
        assets = [
            make_asset("weak", methods=[DiscoveryMethod.ENRICHMENT], depth=2),
            make_asset("strong", atype=AssetType.DOMAIN,
                       methods=[DiscoveryMethod.SEED], depth=0),
            make_asset("mid", methods=[DiscoveryMethod.CT_LOG], depth=1),
        ]
        ordered = score_all(assets, total_seeds=1)
        confidences = [a.confidence for a in ordered]
        assert confidences == sorted(confidences, reverse=True)
        assert ordered[0].value == "strong"

    def test_in_scope_threshold(self):
        a = make_asset("x.example.com", methods=[DiscoveryMethod.CT_LOG], depth=1)
        score(a, 1)
        assert in_scope(a, threshold=0.5) is True
        assert in_scope(a, threshold=0.99) is False

    def test_low_confidence_flagged_out_of_scope(self):
        a = make_asset("maybe.example.com",
                       methods=[DiscoveryMethod.ENRICHMENT], depth=3)
        score(a, 1)
        assert in_scope(a) is False
