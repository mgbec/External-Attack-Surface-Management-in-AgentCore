"""Optional enrichment from internet-wide scan databases.

These sources (Shodan, Censys) query a third party's pre-collected scan data,
so the target is never touched. They are OFF by default because they consume
paid API quotas. Keys are read from config/env; if absent or the client
library is missing, enrichment is skipped silently so the free core still runs.
"""
