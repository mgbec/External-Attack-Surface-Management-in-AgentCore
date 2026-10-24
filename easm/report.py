"""Render a scan result (and optional change diff) to Markdown or HTML.

Dependency-free on purpose: pure-Python string building, no templating engine,
so it adds nothing to the runtime image. Input is the dict produced by
``ScanResult.to_dict()`` (see models.py) and, optionally, the diff dict from
``schedule_scan.compute_diff``.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#7c1313",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#2563eb",
    "info": "#4b5563",
}


# ==========================================================================
# Shared helpers
# ==========================================================================
def _sorted_findings(result: dict) -> list[dict]:
    return sorted(
        result.get("findings", []),
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9),
    )


def _severity_counts(result: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in result.get("findings", []):
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _confidence_band(c: float) -> str:
    if c >= 0.8:
        return "high"
    if c >= 0.5:
        return "medium"
    return "low"


# ==========================================================================
# Markdown
# ==========================================================================
def to_markdown(result: dict, diff: dict | None = None, llm_report: str | None = None) -> str:
    stats = result.get("stats", {})
    lines: list[str] = []
    a = lines.append

    a("# External Attack Surface Report")
    a("")
    a(f"**Seeds:** {', '.join(result.get('seeds', [])) or '(none)'}  ")
    a(f"**Scan started:** {result.get('started_at', '?')}  ")
    a(f"**Scan finished:** {result.get('finished_at', '?')}  ")
    a(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    a("")

    # Summary
    a("## Summary")
    a("")
    a(f"- Total assets discovered: **{stats.get('total_assets', 0)}**")
    a(f"- High-confidence (in-scope) assets: **{stats.get('in_scope_assets', 0)}**")
    a(f"- Total findings: **{stats.get('total_findings', 0)}**")
    sev_counts = _severity_counts(result)
    if sev_counts:
        parts = [f"{sev}: {n}" for sev, n in sorted(
            sev_counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))]
        a(f"- Findings by severity: {', '.join(parts)}")
    a("")

    # Change report
    if diff is not None:
        a("## Changes Since Last Scan")
        a("")
        if diff.get("baseline"):
            a("_First scan — baseline established, nothing to compare against._")
        else:
            a(f"- New assets: **{len(diff.get('new_assets', []))}**")
            a(f"- Removed assets: **{len(diff.get('removed_assets', []))}**")
            a(f"- Newly live assets: **{len(diff.get('newly_live_assets', []))}**")
            a(f"- New findings: **{len(diff.get('new_findings', []))}**")
            a(f"- Resolved findings: **{len(diff.get('resolved_findings', []))}**")
            if diff.get("new_findings"):
                a("")
                a("**New findings this scan:**")
                for nf in diff["new_findings"]:
                    a(f"- `{nf['asset']}` — {nf['title']}")
            if diff.get("new_assets"):
                a("")
                a("**New assets this scan:**")
                for v in diff["new_assets"][:50]:
                    a(f"- `{v}`")
        a("")

    # Findings
    a("## Findings")
    a("")
    findings = _sorted_findings(result)
    if not findings:
        a("_No findings._")
    else:
        a("| Severity | Asset | Finding | Recommendation |")
        a("|---|---|---|---|")
        for f in findings:
            sev = f.get("severity", "info").upper()
            a(f"| {sev} | `{f.get('asset','')}` | {_md_cell(f.get('title',''))} "
              f"| {_md_cell(f.get('recommendation',''))} |")
    a("")

    # Asset inventory
    a("## Asset Inventory")
    a("")
    a("| Confidence | Asset | Type | Seeds | IPs | Ports |")
    a("|---|---|---|---|---|---|")
    for asset in result.get("assets", []):
        ips = ", ".join(asset.get("ip_addresses", [])[:4])
        ports = ", ".join(str(p) for p in asset.get("ports", []))
        seeds = ", ".join(asset.get("discovered_from", []))
        a(f"| {asset.get('confidence', 0):.2f} | `{asset.get('value','')}` "
          f"| {asset.get('asset_type','')} | {_md_cell(seeds)} "
          f"| {_md_cell(ips)} | {ports} |")
    a("")

    if llm_report:
        a("## Analyst Report")
        a("")
        a(llm_report.strip())
        a("")

    return "\n".join(lines)


def _md_cell(text: str) -> str:
    """Escape pipes/newlines so table cells stay intact."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


# ==========================================================================
# HTML (self-contained, inline CSS)
# ==========================================================================
def to_html(result: dict, diff: dict | None = None, llm_report: str | None = None) -> str:
    stats = result.get("stats", {})
    e = html.escape

    def badge(sev: str) -> str:
        color = SEVERITY_COLOR.get(sev, "#4b5563")
        return (f'<span class="badge" style="background:{color}">'
                f'{e(sev.upper())}</span>')

    parts: list[str] = []
    p = parts.append

    p("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    p("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    p("<title>External Attack Surface Report</title>")
    p("<style>" + _CSS + "</style></head><body><div class='wrap'>")

    p("<h1>External Attack Surface Report</h1>")
    p("<div class='meta'>")
    p(f"<div><strong>Seeds:</strong> {e(', '.join(result.get('seeds', [])) or '(none)')}</div>")
    p(f"<div><strong>Started:</strong> {e(str(result.get('started_at','?')))}</div>")
    p(f"<div><strong>Finished:</strong> {e(str(result.get('finished_at','?')))}</div>")
    p("</div>")

    # Summary cards
    sev_counts = _severity_counts(result)
    p("<div class='cards'>")
    p(_card("Total assets", stats.get("total_assets", 0)))
    p(_card("In-scope assets", stats.get("in_scope_assets", 0)))
    p(_card("Findings", stats.get("total_findings", 0)))
    for sev in ("critical", "high", "medium", "low"):
        if sev_counts.get(sev):
            p(_card(sev.capitalize(), sev_counts[sev], color=SEVERITY_COLOR[sev]))
    p("</div>")

    # Change report
    if diff is not None:
        p("<h2>Changes Since Last Scan</h2>")
        if diff.get("baseline"):
            p("<p class='muted'>First scan — baseline established.</p>")
        else:
            p("<div class='cards'>")
            p(_card("New assets", len(diff.get("new_assets", [])), color="#2563eb"))
            p(_card("Removed assets", len(diff.get("removed_assets", []))))
            p(_card("Newly live", len(diff.get("newly_live_assets", [])), color="#b45309"))
            p(_card("New findings", len(diff.get("new_findings", [])), color="#b91c1c"))
            p(_card("Resolved findings", len(diff.get("resolved_findings", [])), color="#15803d"))
            p("</div>")
            if diff.get("new_findings"):
                p("<p><strong>New findings this scan:</strong></p><ul>")
                for nf in diff["new_findings"]:
                    p(f"<li><code>{e(nf['asset'])}</code> — {e(nf['title'])}</li>")
                p("</ul>")

    # Findings table
    p("<h2>Findings</h2>")
    findings = _sorted_findings(result)
    if not findings:
        p("<p class='muted'>No findings.</p>")
    else:
        p("<table><thead><tr><th>Severity</th><th>Asset</th>"
          "<th>Finding</th><th>Recommendation</th></tr></thead><tbody>")
        for f in findings:
            sev = f.get("severity", "info")
            p("<tr>"
              f"<td>{badge(sev)}</td>"
              f"<td><code>{e(f.get('asset',''))}</code></td>"
              f"<td>{e(f.get('title',''))}<div class='desc'>{e(f.get('description',''))}</div></td>"
              f"<td>{e(f.get('recommendation',''))}</td>"
              "</tr>")
        p("</tbody></table>")

    # Inventory table
    p("<h2>Asset Inventory</h2>")
    p("<table><thead><tr><th>Confidence</th><th>Asset</th><th>Type</th>"
      "<th>Seeds</th><th>IPs</th><th>Ports</th></tr></thead><tbody>")
    for asset in result.get("assets", []):
        c = asset.get("confidence", 0.0)
        band = _confidence_band(c)
        ips = ", ".join(asset.get("ip_addresses", [])[:4])
        ports = ", ".join(str(x) for x in asset.get("ports", []))
        seeds = ", ".join(asset.get("discovered_from", []))
        p("<tr>"
          f"<td><span class='conf conf-{band}'>{c:.2f}</span></td>"
          f"<td><code>{e(asset.get('value',''))}</code></td>"
          f"<td>{e(asset.get('asset_type',''))}</td>"
          f"<td>{e(seeds)}</td>"
          f"<td>{e(ips)}</td>"
          f"<td>{e(ports)}</td>"
          "</tr>")
    p("</tbody></table>")

    if llm_report:
        p("<h2>Analyst Report</h2>")
        p(f"<pre class='report'>{e(llm_report.strip())}</pre>")

    p(f"<footer>Generated {e(datetime.now(timezone.utc).isoformat())} "
      "by EASM-AgentCore</footer>")
    p("</div></body></html>")
    return "".join(parts)


def _card(label: str, value: Any, color: str = "#111827") -> str:
    return (f"<div class='card'><div class='num' style='color:{color}'>"
            f"{html.escape(str(value))}</div>"
            f"<div class='lbl'>{html.escape(label)}</div></div>")


_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; font-family: -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
       background:#f8fafc; color:#111827; }
.wrap { max-width:1100px; margin:0 auto; padding:28px 20px 60px; }
h1 { font-size:26px; margin:0 0 4px; }
h2 { font-size:19px; margin:34px 0 12px; border-bottom:1px solid #e5e7eb; padding-bottom:6px; }
.meta { display:flex; flex-wrap:wrap; gap:16px; color:#4b5563; font-size:13px; margin:8px 0 20px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:14px 18px;
        min-width:120px; box-shadow:0 1px 2px rgba(0,0,0,.04); }
.card .num { font-size:26px; font-weight:700; line-height:1; }
.card .lbl { font-size:12px; color:#6b7280; margin-top:6px; text-transform:uppercase; letter-spacing:.04em; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e5e7eb;
        border-radius:10px; overflow:hidden; font-size:13px; }
th,td { text-align:left; padding:9px 12px; border-bottom:1px solid #f1f5f9; vertical-align:top; }
th { background:#f1f5f9; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:#475569; }
tr:last-child td { border-bottom:none; }
code { background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:12px; }
.badge { color:#fff; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }
.desc { color:#6b7280; font-size:12px; margin-top:3px; }
.conf { font-weight:700; padding:2px 7px; border-radius:6px; }
.conf-high { background:#dcfce7; color:#166534; }
.conf-medium { background:#fef9c3; color:#854d0e; }
.conf-low { background:#fee2e2; color:#991b1b; }
.muted { color:#6b7280; }
.report { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:16px;
          white-space:pre-wrap; font-size:13px; line-height:1.5; }
footer { margin-top:40px; color:#9ca3af; font-size:12px; text-align:center; }
@media (prefers-color-scheme: dark) {
  body { background:#0b1120; color:#e5e7eb; }
  .card,table,.report { background:#111827; border-color:#1f2937; }
  th { background:#1f2937; color:#9ca3af; }
  th,td { border-color:#1f2937; }
  code { background:#1f2937; }
  h2 { border-color:#1f2937; }
}
"""


# ==========================================================================
# Convenience
# ==========================================================================
def render(result: dict, fmt: str = "html", *, diff: dict | None = None,
           llm_report: str | None = None) -> str:
    fmt = fmt.lower()
    if fmt in ("md", "markdown"):
        return to_markdown(result, diff=diff, llm_report=llm_report)
    if fmt == "html":
        return to_html(result, diff=diff, llm_report=llm_report)
    raise ValueError(f"Unknown report format: {fmt!r} (use 'html' or 'md')")
