"""Strands agent hosted on Bedrock AgentCore Runtime.

The deterministic pipeline does all the network discovery and produces an
objective inventory + findings. The LLM's job is narrow and cheap:
  - reason about attribution (which low-confidence assets look in/out of scope)
  - prioritize findings into an executive summary
  - produce a readable report

Because the model only ever sees a compact JSON summary (not raw scan traffic),
token usage - and therefore cost - stays small regardless of org size. A small
model (Claude 3.5 Haiku by default) is more than capable of this triage task.

Invoke contract (POST /invocations):
    {"prompt": "<seeds or instruction>"}                      # freeform
  or structured:
    {"seeds": {"domains": [...], ...}, "options": {...}}       # explicit config
"""

from __future__ import annotations

import asyncio
import json
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent

from .config import ScanConfig
from .pipeline import run_scan

app = BedrockAgentCoreApp()

SYSTEM_PROMPT = """You are an External Attack Surface Management (EASM) analyst.
You are given the results of a passive discovery scan as JSON: an asset
inventory (each with a confidence score 0-1 indicating how likely it belongs to
the organization) and a list of deterministic findings.

Your tasks:
1. Write a short executive summary of the organization's external exposure.
2. Prioritize the findings by real-world risk (not just the labelled severity),
   explaining why the top ones matter.
3. Call out assets with LOW confidence (< 0.5) that should be manually verified
   for ownership before being treated as in-scope.
4. Note any cross-domain patterns (shared netblocks, shared certs) visible in
   the data.

Rules:
- Do NOT invent assets or findings that are not in the data.
- Be concise and specific. Reference assets by name.
- If the data is empty, say so plainly.
"""

_DEFAULT_MODEL = os.getenv("EASM_MODEL_ID", "us.anthropic.claude-3-5-haiku-20241022-v1:0")


def _build_config(request: dict) -> ScanConfig:
    """Accept either a structured config or a freeform prompt of domains."""
    if isinstance(request, dict) and ("seeds" in request or "options" in request):
        data = dict(request)
    else:
        prompt = ""
        if isinstance(request, dict):
            prompt = request.get("prompt", "") or ""
        elif isinstance(request, str):
            prompt = request
        # Pull domain-like tokens out of the freeform prompt.
        tokens = [
            t.strip().strip(",")
            for t in prompt.replace("\n", " ").split(" ")
            if "." in t and " " not in t
        ]
        data = {"seeds": {"domains": tokens}}

    data.setdefault("options", {})
    data["options"].setdefault("model_id", _DEFAULT_MODEL)
    return ScanConfig.from_dict(data)


def _summarize_for_model(result_dict: dict, max_assets: int = 120) -> dict:
    """Trim the scan result to a compact payload to keep token cost low."""
    assets = result_dict.get("assets", [])[:max_assets]
    slim_assets = [
        {
            "value": a["value"],
            "type": a["asset_type"],
            "confidence": a["confidence"],
            "from_seeds": a["discovered_from"],
            "ips": a["ip_addresses"][:5],
            "ports": a["ports"],
            "netblock": a.get("attributes", {}).get("netblock"),
        }
        for a in assets
    ]
    return {
        "seeds": result_dict["seeds"],
        "stats": result_dict["stats"],
        "assets": slim_assets,
        "findings": result_dict["findings"],
    }


@app.entrypoint
async def handler(request):
    """AgentCore entrypoint. Runs the scan, then has the model triage + report."""
    config = _build_config(request if isinstance(request, dict) else {"prompt": str(request)})

    if not config.seeds.domains and not config.seeds.ip_ranges:
        yield {
            "type": "error",
            "message": "No seed domains provided. Send {\"seeds\": {\"domains\": [...]}}.",
        }
        return

    # 1. Deterministic scan (no model tokens used here).
    yield {"type": "status", "message": f"Scanning {len(config.seeds.domains)} seed domain(s)..."}
    result = await run_scan(config)
    result_dict = result.to_dict()

    # 2. Emit the raw structured result so callers get machine-readable output.
    yield {"type": "scan_result", "data": result_dict}

    # 3. LLM triage/report over a compact summary.
    summary = _summarize_for_model(result_dict)
    agent = Agent(model=config.options.model_id, system_prompt=SYSTEM_PROMPT)
    user_msg = (
        "Here is the EASM scan output as JSON. Produce the report:\n\n"
        + json.dumps(summary, separators=(",", ":"))
    )

    async for event in agent.stream_async(user_msg):
        # Strands streams dict events; forward text deltas to the caller.
        if isinstance(event, dict) and "data" in event:
            yield {"type": "report_delta", "text": event["data"]}
        else:
            yield event


if __name__ == "__main__":
    app.run()
