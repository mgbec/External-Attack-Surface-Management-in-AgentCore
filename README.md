# EASM-AgentCore

A cheap **External Attack Surface Management (EASM)** tool built on **Amazon Bedrock AgentCore**.

Give it a set of root domains. It discovers the organization's internet-facing
assets through **passive** data sources, scores how confidently each asset belongs
to the org, detects common exposures, and uses a small Bedrock model to triage
and write a prioritized report.

The design goal is **low cost**: all discovery uses free public data sources, the
LLM only ever sees a compact summary (so token spend is tiny), and the deployment
avoids the usual always-on cost traps (no VPC, no NAT gateway, no Browser/Code
Interpreter).

---

## How it works

You provide **seeds** (one or more root domains, optionally org names and known
IP ranges). The tool expands each seed into a full asset inventory — you do **not**
need an asset list up front; the inventory is the *output*.

```
seeds: [example.com, example.net, ...]
   │
   ├─ CT logs (crt.sh) ───────► subdomains        [passive, free]
   ├─ DNS resolve ────────────► IPs, CNAMEs        [passive, free]
   ├─ TLS cert inspect ───────► SANs (recurse) + cert findings   [light-active, free]
   ├─ HTTP inspect ───────────► header/exposure findings         [light-active, free]
   ├─ RDAP ───────────────────► domain owner + IP → netblock/ASN [passive, free]
   └─ (optional) Shodan/Censys► ports/services     [3rd-party DB, off by default]
         │
         ▼
   merge + dedup ──► attribution confidence scoring ──► deterministic findings
         │
         ▼
   Bedrock (small model): triage + prioritize + report   [the only token spend]
```

### Passive discovery

"Passive" means we query **third parties and public records**, not the target's
own infrastructure. CT logs, DNS, and RDAP never touch the target. TLS and HTTP
inspection send only ordinary, browser-like requests, and are used only to
inspect assets attributed to the org. This keeps the tool safe and avoids
tripping AWS's acceptable-use policy. (Active port scanning of assets you don't
own is intentionally **not** included; use Shodan/Censys enrichment for port
data instead, which reads a third party's existing scan results.)

### Multi-seed attribution

Each asset records **which seeds led to it** and gets a `confidence` score
(0.0–1.0) from: the strength of the discovery method, how many independent seeds
corroborate it, and its depth from a seed. Assets below 0.5 are reported but
flagged for manual ownership verification rather than asserted as in-scope.

---

## Project layout

```
easm/
  config.py            # scan config model + loading
  models.py            # Asset / Finding / ScanResult
  attribution.py       # merge/dedup + confidence scoring
  findings.py          # deterministic exposure rules
  report.py            # HTML / Markdown report renderer (no deps)
  pipeline.py          # orchestration (the scan engine)
  agent.py             # Strands agent + AgentCore entrypoint
  discovery/
    ct_logs.py  dns.py  rdap.py  tls.py  http.py
  enrich/
    scanners.py        # optional Shodan/Censys
run_local.py           # free local harness (no Bedrock needed)
schedule_scan.py       # scheduled scan + change detection (local or remote)
seeds.example.json     # sample multi-seed config
tests/                 # unit tests (attribution + findings)
Dockerfile             # AgentCore Runtime container (manual path)
deploy/bedrock-invoke-policy.json   # least-privilege IAM for the model
```

---

## Run locally (free)

The local harness runs the full discovery pipeline **without** calling Bedrock,
so iterating costs nothing.

```bash
python -m venv .venv
# Windows:  .\.venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install dnspython httpx cryptography      # core discovery only

python run_local.py example.com example.net
python run_local.py --config seeds.example.json --out scan-output/result.json
```

Add `--report` to also run the Bedrock triage locally (needs AWS credentials and
model access):

```bash
pip install -r requirements.txt     # adds bedrock-agentcore + strands-agents
python run_local.py example.com --report
```

### Config

`seeds.example.json`:

```json
{
  "seeds": {
    "domains": ["example.com", "example.net"],
    "org_names": ["Example Corp"],
    "ip_ranges": []
  },
  "options": {
    "max_depth": 2,
    "reverse_whois": "flag_only",
    "max_assets": 2000,
    "inspect_http": true,
    "inspect_tls": true,
    "enrichment": { "shodan": false, "censys": false },
    "model_id": "us.anthropic.claude-3-5-haiku-20241022-v1:0"
  }
}
```

Optional enrichment keys are read from the environment, never committed:
`SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`.

---

## Deploy to AgentCore Runtime

### Prerequisites
- AWS account with credentials configured.
- Bedrock model access enabled for your chosen model (default: Claude 3.5 Haiku).
- Python 3.10+.

### Option A — AgentCore CLI (recommended)

```bash
npm i -g @aws/agentcore
agentcore configure --entrypoint easm/agent.py      # first time
agentcore deploy
```

The CLI packages the code, builds the container, creates the execution role, and
deploys the runtime. Attach `deploy/bedrock-invoke-policy.json` to the execution
role (named `AmazonBedrockAgentCoreSDKRuntime-*`) to grant least-privilege model
access.

### Option B — Container (manual)

```bash
docker build -t easm-agent .
# push to ECR and create the runtime with boto3 / the bedrock-agentcore-control API
```

### Invoke

Structured:
```json
{ "seeds": { "domains": ["example.com", "example.net"] }, "options": { "max_depth": 2 } }
```
Freeform prompt also works: `{ "prompt": "scan example.com example.net" }`.

The response streams: a `scan_result` event (full machine-readable inventory +
findings) followed by `report_delta` events (the LLM's prioritized report).

---

## Cost notes (why this stays cheap)

| Component | Cost driver | This project |
|---|---|---|
| Discovery sources | — | **$0** — CT logs, DNS, RDAP, TLS, HTTP are all free |
| Bedrock model | tokens | **cents/scan** — small model + only a compact summary is sent |
| AgentCore Runtime | vCPU/memory-seconds while handling a request | small; billed per invocation, not idle |
| **NAT Gateway** | **~$33/mo always-on** | **avoided** — no VPC attached to the runtime |
| AgentCore Browser / Code Interpreter | metered, expensive | **not used** |
| AgentCore Memory | per-event | **not used** (scans are stateless) |
| Shodan / Censys | paid quota | **off by default**; free tier when enabled |

Keeping the runtime out of a customer VPC is the single biggest cost decision:
a NAT gateway would otherwise bill around $33/month even while the agent is idle.
The agent reaches the public internet (crt.sh, DNS, RDAP, targets) directly, so
no VPC/NAT is needed.

To go even cheaper on tokens, switch `model_id` to `us.amazon.nova-lite-v1:0`.

---

## Tests

Unit tests cover the two pieces of pure logic that matter most: attribution
confidence scoring and the deterministic finding rules. They need no network.

```bash
pip install pytest
python -m pytest tests/ -q
```

---

## Reports (HTML / Markdown)

`easm/report.py` renders a scan result into a readable **HTML** page (self-contained,
inline CSS, light/dark) or **Markdown**. It's dependency-free, so it adds nothing
to the runtime image. Both CLIs can emit reports:

```bash
# From a one-off scan:
python run_local.py example.com --html scan-output/report.html --md scan-output/report.md

# From a scheduled scan (reports include the change-diff section):
python schedule_scan.py --config seeds.example.json --out-dir scan-output --html --md
```

With no path given to the scheduler's `--html`/`--md`, reports are written to
`<out-dir>/report-<timestamp>.{html,md}`. The report shows summary cards, a
findings table (severity-coded), the attribution-scored asset inventory, and -
when run from `schedule_scan.py` - what changed since the previous scan. If the
LLM triage text is available it is appended as an "Analyst Report" section.

Render programmatically:

```python
from easm import report
html = report.to_html(scan_result_dict, diff=diff_dict, llm_report="...")
md = report.render(scan_result_dict, "md")
```

---

## Scheduled scans (change detection)

Running an EASM scan on a schedule is valuable because it tells you **what
changed** — a new subdomain, a newly exposed service, a cert that just expired.
`schedule_scan.py` runs a scan, stores a timestamped copy, and diffs it against
the previous run.

```
scan-output/
  history/scan-<timestamp>.json   # every run
  latest.json                     # most recent full result
  diff-<timestamp>.json           # new/removed assets, new/resolved findings
```

```bash
# Free, in-process (good for a cron / Task Scheduler job you control):
python schedule_scan.py --config seeds.example.json --out-dir scan-output

# Invoke the deployed AgentCore runtime instead:
python schedule_scan.py --config seeds.example.json --mode remote \
  --agent-runtime-arn arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/easm-xxxx

# Exit non-zero when new findings appear (to drive an alert/CI job):
python schedule_scan.py --config seeds.example.json --fail-on-new-findings
```

### Scheduling options

**Local machine — cheapest, $0 infra**

- Windows Task Scheduler: create a daily task running
  `.venv\Scripts\python.exe schedule_scan.py --config seeds.example.json`.
- Linux/macOS cron: `0 6 * * * cd /path/to/easm && .venv/bin/python schedule_scan.py --config seeds.example.json`.

**AWS — serverless, pennies/month**

Use **Amazon EventBridge Scheduler** to invoke the deployed AgentCore runtime on
a cron/rate schedule. The scheduler itself is effectively free at daily
frequency; you pay only for the per-invocation runtime seconds and model tokens
of each scan. No always-on compute, no NAT.

1. Deploy the agent (see above) and note its runtime ARN.
2. Create an EventBridge Scheduler schedule (e.g. `rate(1 day)`) whose target is
   the `bedrock-agentcore:InvokeAgentRuntime` API, with an input payload of
   `{"seeds": {"domains": [...]}, "options": {...}}` and a role allowed to
   invoke the runtime.
3. To keep the diff/history, point the schedule at a tiny Lambda that calls
   `schedule_scan.py --mode remote` and writes results to S3, or run the
   scheduler against a small container — whichever fits your stack.

Either way the recurring cost stays dominated by the few cents of model tokens
per scan.

---

## Scope & safety

- Only scan domains your organization owns or is explicitly authorized to assess.
- The tool uses passive sources and ordinary web requests; it does not perform
  intrusive scanning or exploitation.
- Low-confidence assets are flagged, not asserted — always verify ownership
  before acting on them.
```
