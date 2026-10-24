"""Tests for the deterministic finding-detection rules."""

from easm.discovery.dns import DnsRecords
from easm.discovery.http import HttpInfo
from easm.discovery.tls import TlsInfo
from easm.findings import (
    exposed_port_findings,
    from_dns,
    from_http,
    from_tls,
)
from easm.models import Severity


def titles(findings):
    return {f.title for f in findings}


class TestTlsFindings:
    def test_not_connected_yields_nothing(self):
        assert from_tls(TlsInfo(host="x.com", connected=False)) == []

    def test_expired_cert_is_high(self):
        info = TlsInfo(host="x.com", connected=True, expired=True,
                       not_after="2020-01-01T00:00:00+00:00", days_to_expiry=-100)
        f = from_tls(info)
        assert "Expired TLS certificate" in titles(f)
        assert any(x.severity == Severity.HIGH for x in f)

    def test_expiring_soon_is_medium(self):
        info = TlsInfo(host="x.com", connected=True, expired=False, days_to_expiry=10)
        f = from_tls(info)
        assert "TLS certificate expiring soon" in titles(f)
        assert any(x.severity == Severity.MEDIUM for x in f)

    def test_healthy_cert_no_expiry_finding(self):
        info = TlsInfo(host="x.com", connected=True, expired=False, days_to_expiry=200)
        assert "TLS certificate expiring soon" not in titles(from_tls(info))
        assert "Expired TLS certificate" not in titles(from_tls(info))

    def test_self_signed_flagged(self):
        info = TlsInfo(host="x.com", connected=True, self_signed=True, days_to_expiry=200)
        assert "Self-signed TLS certificate" in titles(from_tls(info))

    def test_weak_signature_algorithm_flagged(self):
        info = TlsInfo(host="x.com", connected=True, days_to_expiry=200,
                       signature_algorithm="sha1WithRSAEncryption")
        assert "Weak certificate signature algorithm" in titles(from_tls(info))

    def test_strong_signature_not_flagged(self):
        info = TlsInfo(host="x.com", connected=True, days_to_expiry=200,
                       signature_algorithm="sha256WithRSAEncryption")
        assert "Weak certificate signature algorithm" not in titles(from_tls(info))


class TestDnsFindings:
    def test_dangling_cname_is_high(self):
        rec = DnsRecords(host="old.x.com", cname=["gone.cloudapp.net"],
                         dangling_cname=True, resolves=False)
        f = from_dns(rec)
        assert "Possible dangling CNAME (subdomain takeover risk)" in titles(f)
        assert all(x.severity == Severity.HIGH for x in f)

    def test_resolving_host_no_finding(self):
        rec = DnsRecords(host="x.com", a=["1.2.3.4"], resolves=True)
        assert from_dns(rec) == []


class TestHttpFindings:
    def test_not_reachable_yields_nothing(self):
        assert from_http(HttpInfo(host="x.com", reachable=False)) == []

    def test_missing_hsts_csp_flagged_on_https(self):
        info = HttpInfo(host="x.com", reachable=True, scheme="https", status=200,
                        missing_security_headers=["strict-transport-security",
                                                  "content-security-policy"],
                        final_url="https://x.com")
        assert "Missing security headers" in titles(from_http(info))

    def test_missing_minor_headers_only_not_flagged(self):
        # Missing only non-critical headers should not raise the finding.
        info = HttpInfo(host="x.com", reachable=True, scheme="https", status=200,
                        missing_security_headers=["referrer-policy"],
                        final_url="https://x.com")
        assert "Missing security headers" not in titles(from_http(info))

    def test_version_banner_flagged(self):
        info = HttpInfo(host="x.com", reachable=True, scheme="https", status=200,
                        server="nginx/1.18.0", final_url="https://x.com")
        assert "Server banner leaks version information" in titles(from_http(info))

    def test_banner_without_version_not_flagged(self):
        info = HttpInfo(host="x.com", reachable=True, scheme="https", status=200,
                        server="nginx", final_url="https://x.com")
        assert "Server banner leaks version information" not in titles(from_http(info))

    def test_no_https_redirect_flagged(self):
        info = HttpInfo(host="x.com", reachable=True, scheme="http", status=200,
                        final_url="http://x.com")
        assert "No HTTPS redirect" in titles(from_http(info))


class TestExposedPorts:
    def test_critical_services_high(self):
        f = exposed_port_findings("x.com", {6379})  # Redis
        assert f and f[0].severity == Severity.HIGH

    def test_ssh_is_medium(self):
        f = exposed_port_findings("x.com", {22})
        assert f and f[0].severity == Severity.MEDIUM

    def test_benign_ports_ignored(self):
        assert exposed_port_findings("x.com", {443, 80}) == []

    def test_multiple_sensitive_ports(self):
        f = exposed_port_findings("x.com", {22, 3389, 3306})
        assert len(f) == 3
