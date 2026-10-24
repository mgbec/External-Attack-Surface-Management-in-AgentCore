"""Passive (and light-active) discovery sources.

All core sources query third parties or use ordinary, expected traffic:
  - ct_logs: Certificate Transparency logs (crt.sh)       [passive, free]
  - dns:     DNS record resolution                         [passive, free]
  - rdap:    RDAP registration + ASN/netblock pivot        [passive, free]
  - tls:     TLS certificate inspection                    [light-active, free]
  - http:    HTTP response/header inspection               [light-active, free]
"""
