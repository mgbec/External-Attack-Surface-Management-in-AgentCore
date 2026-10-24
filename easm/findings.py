"""Deterministic finding-detection rules.

These rules run over the enriched inventory and produce Finding objects. They
are intentionally rule-based (not LLM-based) so that the objective, factual
findings are cheap and reproducible. The LLM layer later prioritizes and
explains them - it does not invent findings.
"""

from __future__ import annotations

from .discovery.dns import DnsRecords
from .discovery.http import HttpInfo
from .discovery.tls import TlsInfo
from .models import Finding, Severity

# Warn when a cert expires within this many days.
CERT_EXPIRY_WARN_DAYS = 21

# Server/powered-by banners that leak version detail are worth flagging.
def _banner_leaks_version(value: str | None) -> bool:
    return bool(value) and any(ch.isdigit() for ch in value)


def from_tls(info: TlsInfo) -> list[Finding]:
    out: list[Finding] = []
    if not info.connected:
        return out

    if info.expired:
        out.append(Finding(
            asset=info.host,
            title="Expired TLS certificate",
            severity=Severity.HIGH,
            description=f"The certificate for {info.host} expired on {info.not_after}.",
            evidence={"not_after": info.not_after, "issuer": info.issuer},
            recommendation="Renew or replace the certificate; automate renewal (e.g. ACM/Let's Encrypt).",
        ))
    elif info.days_to_expiry is not None and 0 <= info.days_to_expiry <= CERT_EXPIRY_WARN_DAYS:
        out.append(Finding(
            asset=info.host,
            title="TLS certificate expiring soon",
            severity=Severity.MEDIUM,
            description=f"The certificate for {info.host} expires in {info.days_to_expiry} day(s).",
            evidence={"not_after": info.not_after, "days_to_expiry": info.days_to_expiry},
            recommendation="Schedule renewal before expiry to avoid an outage.",
        ))

    if info.self_signed:
        out.append(Finding(
            asset=info.host,
            title="Self-signed TLS certificate",
            severity=Severity.MEDIUM,
            description=f"{info.host} presents a self-signed certificate.",
            evidence={"issuer": info.issuer, "subject_cn": info.subject_cn},
            recommendation="Use a certificate from a trusted CA for public-facing services.",
        ))

    if info.signature_algorithm and any(
        weak in info.signature_algorithm.lower() for weak in ("md5", "sha1")
    ):
        out.append(Finding(
            asset=info.host,
            title="Weak certificate signature algorithm",
            severity=Severity.MEDIUM,
            description=f"{info.host} uses a weak signature algorithm: {info.signature_algorithm}.",
            evidence={"signature_algorithm": info.signature_algorithm},
            recommendation="Reissue the certificate with SHA-256 or stronger.",
        ))
    return out


def from_dns(rec: DnsRecords) -> list[Finding]:
    out: list[Finding] = []
    if rec.dangling_cname:
        out.append(Finding(
            asset=rec.host,
            title="Possible dangling CNAME (subdomain takeover risk)",
            severity=Severity.HIGH,
            description=(
                f"{rec.host} has a CNAME ({', '.join(rec.cname)}) but does not "
                "resolve to an address. If the target points to a deprovisioned "
                "cloud resource, an attacker may be able to claim it."
            ),
            evidence={"cname": rec.cname},
            recommendation="Remove the DNS record or reclaim the target resource.",
        ))
    return out


def from_http(info: HttpInfo) -> list[Finding]:
    out: list[Finding] = []
    if not info.reachable:
        return out

    # Only treat missing HSTS/CSP as notable on HTTPS responses.
    if info.scheme == "https" and info.missing_security_headers:
        critical_missing = [
            h for h in info.missing_security_headers
            if h in ("strict-transport-security", "content-security-policy")
        ]
        if critical_missing:
            out.append(Finding(
                asset=info.host,
                title="Missing security headers",
                severity=Severity.LOW,
                description=(
                    f"{info.host} is missing: {', '.join(info.missing_security_headers)}."
                ),
                evidence={"missing": info.missing_security_headers, "url": info.final_url},
                recommendation="Add HSTS and a Content-Security-Policy; set X-Content-Type-Options: nosniff.",
            ))

    if _banner_leaks_version(info.server) or _banner_leaks_version(info.powered_by):
        out.append(Finding(
            asset=info.host,
            title="Server banner leaks version information",
            severity=Severity.LOW,
            description=f"{info.host} discloses software versions in response headers.",
            evidence={"server": info.server, "x_powered_by": info.powered_by},
            recommendation="Suppress version details in Server / X-Powered-By headers.",
        ))

    if info.scheme == "http" and not (info.final_url or "").startswith("https"):
        out.append(Finding(
            asset=info.host,
            title="No HTTPS redirect",
            severity=Severity.LOW,
            description=f"{info.host} served content over plain HTTP without redirecting to HTTPS.",
            evidence={"final_url": info.final_url},
            recommendation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
        ))
    return out


def exposed_port_findings(host: str, ports: set[int]) -> list[Finding]:
    """Flag sensitive services exposed to the internet (from enrichment data)."""
    sensitive = {
        3389: "RDP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5900: "VNC",
        445: "SMB", 11211: "Memcached", 2375: "Docker API",
    }
    out: list[Finding] = []
    for port in sorted(ports):
        if port in sensitive:
            svc = sensitive[port]
            sev = Severity.HIGH if port in (23, 3389, 6379, 27017, 9200, 11211, 2375) else Severity.MEDIUM
            out.append(Finding(
                asset=host,
                title=f"Exposed {svc} service (port {port})",
                severity=sev,
                description=f"{host} appears to expose {svc} on port {port} to the internet.",
                evidence={"port": port, "service": svc},
                recommendation=f"Restrict {svc} to trusted networks or place behind a VPN/bastion.",
            ))
    return out
