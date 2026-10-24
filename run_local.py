#!/usr/bin/env python3
"""Local harness for the EASM pipeline.

Runs the deterministic discovery pipeline WITHOUT invoking Bedrock, so you can
iterate for free. The LLM triage layer (agent.py) is only exercised when
deployed or when you explicitly pass --report with AWS credentials configured.

Usage:
    python run_local.py example.com example.net
    python run_local.py --config seeds.example.json
    python run_local.py example.com --out scan-output/result.json
    python run_local.py example.com --report          # also run Bedrock triage
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from easm.config import ScanConfig
from easm.pipeline import run_scan


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run an EASM passive discovery scan locally.")
    p.add_argument("domains", nargs="*", help="Seed root domains (space separated).")
    p.add_argument("--config", help="Path to a JSON scan config (overrides positional domains).")
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--max-assets", type=int, default=2000)
    p.add_argument("--no-http", action="store_true", help="Skip HTTP inspection.")
    p.add_argument("--no-tls", action="store_true", help="Skip TLS inspection.")
    p.add_argument("--out", help="Write full JSON result to this path.")
    p.add_argument("--html", help="Write an HTML report to this path.")
    p.add_argument("--md", help="Write a Markdown report to this path.")
    p.add_argument("--report", action="store_true",
                   help="Also run the Bedrock LLM triage (requires AWS creds).")
    return p.parse_args(argv)


def build_config(args: argparse.Namespace) -> ScanConfig:
    if args.config:
        return ScanConfig.from_json_file(args.config)
    if not args.domains:
        print("error: provide seed domains or --config", file=sys.stderr)
        sys.exit(2)
    return ScanConfig.from_dict({
        "seeds": {"domains": args.domains},
        "options": {
            "max_depth": args.max_depth,
            "max_assets": args.max_assets,
            "inspect_http": not args.no_http,
            "inspect_tls": not args.no_tls,
        },
    })


def print_summary(result_dict: dict) -> None:
    stats = result_dict["stats"]
    print("\n=== EASM Scan Summary ===")
    print(f"Seeds:            {', '.join(result_dict['seeds'])}")
    print(f"Total assets:     {stats.get('total_assets')}")
    print(f"In-scope (>=0.5): {stats.get('in_scope_assets')}")
    print(f"Findings:         {stats.get('total_findings')}")

    print("\n--- Top assets by confidence ---")
    for a in result_dict["assets"][:20]:
        ports = f" ports={a['ports']}" if a["ports"] else ""
        print(f"  [{a['confidence']:.2f}] {a['value']} ({a['asset_type']}) "
              f"from={a['discovered_from']}{ports}")

    if result_dict["findings"]:
        print("\n--- Findings (by severity) ---")
        for f in result_dict["findings"]:
            print(f"  [{f['severity'].upper():8}] {f['asset']}: {f['title']}")
    else:
        print("\nNo findings.")


async def main_async(argv: list[str]) -> int:
    args = parse_args(argv)
    config = build_config(args)

    print(f"Scanning {len(config.seeds.domains)} seed(s): {', '.join(config.seeds.domains)}")
    print("(passive discovery: CT logs, DNS, RDAP, TLS, HTTP)\n")

    result = await run_scan(config)
    result_dict = result.to_dict()
    print_summary(result_dict)

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result_dict, fh, indent=2)
        print(f"\nFull result written to {args.out}")

    llm_text: str | None = None
    if args.report:
        print("\n=== Bedrock LLM triage ===")
        llm_text = await _run_report(config, result_dict)

    # Rendered reports (HTML / Markdown).
    if args.html or args.md:
        from easm import report as report_mod
        if args.html:
            _write(args.html, report_mod.to_html(result_dict, llm_report=llm_text))
            print(f"HTML report written to {args.html}")
        if args.md:
            _write(args.md, report_mod.to_markdown(result_dict, llm_report=llm_text))
            print(f"Markdown report written to {args.md}")

    return 0


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


async def _run_report(config: ScanConfig, result_dict: dict) -> str | None:
    """Optional: exercise the model triage locally. Requires AWS credentials
    and Bedrock model access. Returns the collected report text (or None)."""
    try:
        import json as _json

        from strands import Agent

        from easm.agent import SYSTEM_PROMPT, _summarize_for_model
    except Exception as exc:  # pragma: no cover
        print(f"(skipped - could not import agent deps: {exc})")
        return None

    summary = _summarize_for_model(result_dict)
    agent = Agent(model=config.options.model_id, system_prompt=SYSTEM_PROMPT)
    msg = "Here is the EASM scan output as JSON. Produce the report:\n\n" + _json.dumps(
        summary, separators=(",", ":")
    )
    collected: list[str] = []
    try:
        async for event in agent.stream_async(msg):
            if isinstance(event, dict) and "data" in event:
                print(event["data"], end="", flush=True)
                collected.append(event["data"])
        print()
    except Exception as exc:
        print(f"(report failed - check AWS creds / Bedrock model access: {exc})")
        return None
    return "".join(collected) or None


def main() -> None:
    raise SystemExit(asyncio.run(main_async(sys.argv[1:])))


if __name__ == "__main__":
    main()
