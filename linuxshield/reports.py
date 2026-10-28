"""Report output helpers."""
import json
from html import escape
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], destination: str) -> None:
    Path(destination).write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_html(report: dict[str, Any], destination: str) -> None:
    rows = []
    for finding in report["findings"]:
        rows.append(
            "<tr>"
            f"<td>{escape(str(finding['severity']))}</td>"
            f"<td>{escape(str(finding['title']))}</td>"
            f"<td>{escape(str(finding['details']))}</td>"
            f"<td>{escape(str(finding['recommendation']))}</td>"
            "</tr>"
        )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LinuxShield Audit Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
h1{{margin-bottom:.2rem}} .score{{font-size:1.6rem;font-weight:700}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}} th,td{{border:1px solid #ddd;padding:.65rem;text-align:left;vertical-align:top}}
th{{background:#f3f3f3}} .note{{color:#555}}
</style>
</head>
<body>
<h1>LinuxShield Audit Report</h1>
<p>Host: {escape(str(report['host']))} · Platform: {escape(str(report['platform']))}</p>
<p class="score">Heuristic score: {int(report['score'])}/100</p>
<p class="note">{escape(str(report['note']))}</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Details</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""
    Path(destination).write_text(document, encoding="utf-8")
