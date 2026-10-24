"""TLS certificate inspection.

Performing a TLS handshake and reading the presented certificate is ordinary,
expected web traffic (indistinguishable from a browser). It yields:
  - Subject Alternative Names (SANs) -> more hostnames to feed back into
    discovery (recursive expansion).
  - notAfter / notBefore -> expired or not-yet-valid certs (findings).
  - issuer / signature algorithm -> weak-crypto signals.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class TlsInfo:
    host: str
    port: int = 443
    connected: bool = False
    subject_cn: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    expired: bool = False
    days_to_expiry: int | None = None
    self_signed: bool = False
    signature_algorithm: str | None = None
    error: str | None = None


def _fetch_cert_der(host: str, port: int, timeout: float) -> bytes:
    """Blocking cert fetch. We deliberately do NOT verify the cert here - the
    goal is to inspect whatever is presented, including expired/invalid ones."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


async def inspect(host: str, *, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    info = TlsInfo(host=host, port=port)
    try:
        der = await asyncio.wait_for(
            asyncio.to_thread(_fetch_cert_der, host, port, timeout),
            timeout=timeout + 1,
        )
    except (socket.gaierror, socket.timeout, OSError, ssl.SSLError,
            asyncio.TimeoutError) as exc:
        info.error = type(exc).__name__
        return info

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        info.connected = True
        info.subject_cn = _name_cn(cert.subject)
        info.issuer = _name_cn(cert.issuer)
        info.self_signed = cert.subject == cert.issuer
        info.signature_algorithm = cert.signature_algorithm_oid._name

        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        info.not_after = not_after.isoformat()
        info.not_before = not_before.isoformat()
        now = datetime.now(timezone.utc)
        info.expired = not_after < now
        info.days_to_expiry = (not_after - now).days

        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = []
            for n in ext.value.get_values_for_type(x509.DNSName):
                # Strip a leading wildcard label: "*.example.com" -> "example.com".
                host = n.lower().removeprefix("*.").rstrip(".")
                if host and "." in host:
                    sans.append(host)
            info.sans = sans
        except x509.ExtensionNotFound:
            info.sans = []
    except Exception as exc:  # malformed cert - record and move on
        info.error = f"parse:{type(exc).__name__}"
    return info


def _name_cn(name: x509.Name) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None
