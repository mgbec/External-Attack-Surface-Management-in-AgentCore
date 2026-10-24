#!/usr/bin/env python3
"""Scheduled scan driver.

Runs a scan and persists a timestamped result, then diffs it against the most
recent previous scan so you see what CHANGED (new assets, resolved/removed
assets, new findings) rather than re-reading the whole attack surface each time.
Change detection is the main reason to run an EASM tool on a schedule.

Two execution modes:

  --mode local   (default)
      Run the discovery pipeline in-process. Free, no AWS needed. Good for a
      cron job / Task Scheduler entry on a box you control.

  --mode remote
      Invoke an already-deployed AgentCore runtime via boto3
      (bedrock-agentcore InvokeAgentRuntime) and store its scan_result. Use
      this when EventBridge Scheduler (or any scheduler) should trigger the
      hosted agent. Requires --agent-runtime-arn and AWS credentials.

Output layout:
    <out-dir>/
      history/scan-YYYYMMDDTHHMMSSZ.json     # every run, timestamped
      latest.json                            # most recent full result
      diff-YYYYMMDDTHHMMSSZ.json             # change report vs previous run

Typical scheduled invocation:
    python schedule_scan.py --config seeds.example.json --out-dir scan-output
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import glob
import json
import os
import sys

from easm.config import ScanConfig


# --------------------------------------------------------------------------
# Running a scan
# --------------------------------------------------------------------------
async def run_local(config: ScanConfig) -> dict:
    from easm.pipeline import run_scan
    result = await run_scan(config)
    return result.to_dict()


def run_remote(config: ScanConfig, agent_runtime_arn: str, region: str | None) -> dict:
    """Invoke a deployed AgentCore runtime and return its scan_result payload."""
    import boto3

    client = boto3.client(
        "bedrock-agentcore", region_name=region or os.getenv("AWS_REGION")
    )
    payload = {
        "seeds": {
            "domains": config.seeds.domains,
            "org_names": config.seeds.org_names,
            "ip_ranges": config.seeds.ip_ranges,
        },
        "options": {
            "max_depth": config.options.max_depth,
            "max_assets": config.options.max_assets,
            "inspect_http": config.options.inspect_http,
            "inspect_tls": config.options.inspect_tls,
            "model_id": config.options.model_id,
        },
    }
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=agent_runtime_arn,
        payload=json.dumps(payload).encode("utf-8"),
        contentType="application/json",
        accept="application/json",
    )

    # The runtime streams events; collect the scan_result event.
    scan_result: dict | None = None
    body = resp.get("response") or resp.get("body")
    for raw in _iter_event_lines(body):
        try:
            event = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(event, dict) and event.get("type") == "scan_result":
            scan_result = event.get("data")
    if scan_result is None:
        raise RuntimeError("No scan_result event returned by the agent runtime.")
    return scan_result


def _iter_event_lines(body):
    """Yield text lines from a streaming/byte/iterable response body."""
    if body is None:
        return
    if hasattr(body, "iter_lines"):
        for line in body.iter_lines():
            yield line.decode("utf-8") if isinstance(line, bytes) else line
        return
    if isinstance(body, (bytes, bytearray)):
        text = body.decode("utf-8")
    elif isinstance(body, str):
        text = body
    else:
        # botocore StreamingBody
        text = body.read().decode("utf-8") if hasattr(body, "read") else str(body)
    for line in text.splitlines():
        line = line.strip()
        # Tolerate Server-Sent-Events framing: "data: {...}"
        if line.startswith("data:"):
            line = line[5:].strip()
        if line:
            yield line


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------
def _asset_values(result: dict) -> set[str]:
    return {a["value"] for a in result.get("assets", [])}


def _finding_keys(result: dict) -> set[tuple]:
    return {(f["asset"], f["title"]) for f in result.get("findings", [])}


def _resolving(result: dict) -> set[str]:
    return {a["value"] for a in result.get("assets", []) if a.get("ip_addresses")}


def compute_diff(current: dict, previous: dict | None) -> dict:
    now_assets = _asset_values(current)
    now_findings = _finding_keys(current)
    now_live = _resolving(current)

    if previous is None:
        return {
            "baseline": True,
            "message": "First scan - no previous result to diff against.",
            "new_assets": sorted(now_assets),
            "removed_assets": [],
            "new_findings": [{"asset": a, "title": t} for a, t in sorted(now_findings)],
            "resolved_findings": [],
            "newly_live_assets": sorted(now_live),
        }

    prev_assets = _asset_values(previous)
    prev_findings = _finding_keys(previous)
    prev_live = _resolving(previous)

    return {
        "baseline": False,
        "new_assets": sorted(now_assets - prev_assets),
        "removed_assets": sorted(prev_assets - now_assets),
        "new_findings": [
            {"asset": a, "title": t} for a, t in sorted(now_findings - prev_findings)
        ],
        "resolved_findings": [
            {"asset": a, "title": t} for a, t in sorted(prev_findings - now_findings)
        ],
        "newly_live_assets": sorted(now_live - prev_live),
        "went_dark_assets": sorted(prev_live - now_live),
    }


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
def _load_previous(history_dir: str, exclude: str | None) -> dict | None:
    files = sorted(glob.glob(os.path.join(history_dir, "scan-*.json")))
    files = [f for f in files if f != exclude]
    if not files:
        return None
    with open(files[-1], "r", encoding="utf-8") as fh:
        return json.load(fh)


def persist(result: dict, out_dir: str) -> dict:
    history_dir = os.path.join(out_dir, "history")
    os.makedirs(history_dir, exist_ok=True)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    current_path = os.path.join(history_dir, f"scan-{stamp}.json")

    previous = _load_previous(history_dir, exclude=current_path)

    with open(current_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(os.path.join(out_dir, "latest.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    diff = compute_diff(result, previous)
    diff_path = os.path.join(out_dir, f"diff-{stamp}.json")
    with open(diff_path, "w", encoding="utf-8") as fh:
        json.dump(diff, fh, indent=2)

    return {"current": current_path, "diff": diff_path, "diff_data": diff, "stamp": stamp}


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def print_diff(diff: dict) -> None:
    print("\n=== Change report ===")
    if diff.get("baseline"):
        print(diff["message"])
        print(f"Baseline assets:   {len(diff['new_assets'])}")
        print(f"Baseline findings: {len(diff['new_findings'])}")
        return
    print(f"New assets:        {len(diff['new_assets'])}  {diff['new_assets'][:10]}")
    print(f"Removed assets:    {len(diff['removed_assets'])}  {diff['removed_assets'][:10]}")
    print(f"Newly live:        {len(diff['newly_live_assets'])}  {diff['newly_live_assets'][:10]}")
    print(f"New findings:      {len(diff['new_findings'])}")
    for nf in diff["new_findings"][:15]:
        print(f"    + {nf['asset']}: {nf['title']}")
    print(f"Resolved findings: {len(diff['resolved_findings'])}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run a scheduled EASM scan with change detection.")
    p.add_argument("--config", required=True, help="Path to a JSON scan config.")
    p.add_argument("--out-dir", default="scan-output", help="Where to store history + diffs.")
    p.add_argument("--mode", choices=["local", "remote"], default="local")
    p.add_argument("--agent-runtime-arn", help="AgentCore runtime ARN (remote mode).")
    p.add_argument("--region", help="AWS region (remote mode).")
    # Non-zero exit when new findings appear - useful to fail a CI/alert job.
    p.add_argument("--fail-on-new-findings", action="store_true")
    # Rendered reports (include the change diff). "auto" writes into out-dir.
    p.add_argument("--html", nargs="?", const="auto",
                   help="Write an HTML report (optionally to PATH; default: <out-dir>/report-<ts>.html).")
    p.add_argument("--md", nargs="?", const="auto",
                   help="Write a Markdown report (optionally to PATH; default: <out-dir>/report-<ts>.md).")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config = ScanConfig.from_json_file(args.config)

    if args.mode == "remote":
        if not args.agent_runtime_arn:
            print("error: --agent-runtime-arn is required in remote mode", file=sys.stderr)
            return 2
        result = run_remote(config, args.agent_runtime_arn, args.region)
    else:
        result = asyncio.run(run_local(config))

    saved = persist(result, args.out_dir)
    print_diff(saved["diff_data"])
    print(f"\nSaved: {saved['current']}")
    print(f"Diff:  {saved['diff']}")

    # Rendered reports include the change diff.
    if args.html or args.md:
        from easm import report as report_mod
        stamp = saved["stamp"]
        diff_data = saved["diff_data"]
        if args.html:
            path = args.html if args.html != "auto" else os.path.join(
                args.out_dir, f"report-{stamp}.html")
            _write_text(path, report_mod.to_html(result, diff=diff_data))
            print(f"HTML report: {path}")
        if args.md:
            path = args.md if args.md != "auto" else os.path.join(
                args.out_dir, f"report-{stamp}.md")
            _write_text(path, report_mod.to_markdown(result, diff=diff_data))
            print(f"Markdown report: {path}")

    if args.fail_on_new_findings and not saved["diff_data"].get("baseline"):
        if saved["diff_data"]["new_findings"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
