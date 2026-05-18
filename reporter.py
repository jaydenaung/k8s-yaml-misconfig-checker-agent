# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
reporter.py — Render findings into a readable Markdown report
"""

from pathlib import Path
from typing import List, Dict
from datetime import datetime


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def render_report(filename: str, resources: List[Dict], findings: List[Dict]) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    kinds = [r.get("kind", "Unknown") for r in resources]

    # Sort findings by severity
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))

    # Count by severity
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    static_count = sum(1 for f in findings if f.get("source") == "static")
    ai_count = sum(1 for f in findings if f.get("source") == "claude-ai")

    lines = []

    # Header
    lines += [
        f"# K8s Security Analysis Report",
        f"",
        f"**File:** `{filename}`  ",
        f"**Scanned:** {now}  ",
        f"**Resources:** {', '.join(kinds)}  ",
        f"**Total findings:** {len(findings)} ({static_count} static, {ai_count} AI-identified)",
        f"",
    ]

    # Summary table
    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, icon in SEVERITY_ICON.items():
        count = counts.get(sev, 0)
        lines.append(f"| {icon} {sev} | {count} |")
    lines.append("")

    # Risk score (simple weighted)
    score = (
        counts.get("CRITICAL", 0) * 10 +
        counts.get("HIGH", 0) * 5 +
        counts.get("MEDIUM", 0) * 2 +
        counts.get("LOW", 0) * 1
    )
    if score == 0:
        risk_label = "PASS — No significant issues found"
    elif score <= 5:
        risk_label = "LOW RISK"
    elif score <= 15:
        risk_label = "MEDIUM RISK"
    elif score <= 30:
        risk_label = "HIGH RISK"
    else:
        risk_label = "CRITICAL RISK — Do not deploy"

    lines += [
        f"**Risk score:** {score} — {risk_label}",
        "",
    ]

    if not findings:
        lines += [
            "## Findings",
            "",
            "> No security misconfigurations detected. Good work!",
            "",
        ]
        return "\n".join(lines)

    # Findings detail
    lines += ["## Findings", ""]

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "INFO")
        icon = SEVERITY_ICON.get(sev, "⚪")
        source_badge = "[AI]" if f.get("source") == "claude-ai" else "[static]"

        lines += [
            f"### {i}. {icon} {f.get('title', 'Untitled')} `{source_badge}`",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Check ID** | `{f.get('check_id', 'N/A')}` |",
            f"| **Severity** | {sev} |",
            f"| **Resource** | `{f.get('context', 'N/A')}` |",
        ]
        if f.get("resource_path"):
            lines.append(f"| **Path** | `{f.get('resource_path')}` |")
        lines.append("")

        lines += [
            f"**What's wrong:**  ",
            f"{f.get('detail', '')}",
            "",
            f"**How to fix:**  ",
            f"{f.get('remediation', '')}",
            "",
        ]

        # AI-specific fields
        if f.get("attack_scenario"):
            lines += [
                f"**Attack scenario:** {f.get('attack_scenario')}",
                "",
            ]
        if f.get("telco_relevance"):
            lines += [
                f"**Telco/CNF relevance:** {f.get('telco_relevance')}",
                "",
            ]

        lines.append("---")
        lines.append("")

    # Remediation priority
    criticals = [f for f in sorted_findings if f.get("severity") == "CRITICAL"]
    highs = [f for f in sorted_findings if f.get("severity") == "HIGH"]

    if criticals or highs:
        lines += ["## Remediation priority", ""]
        if criticals:
            lines.append("**Fix immediately (before any deployment):**")
            for f in criticals:
                lines.append(f"- {f.get('title')} — `{f.get('context')}`")
            lines.append("")
        if highs:
            lines.append("**Fix in next sprint:**")
            for f in highs:
                lines.append(f"- {f.get('title')} — `{f.get('context')}`")
            lines.append("")

    lines += [
        "---",
        f"*K8s Misconfiguration Checker — AI-powered security scanner*",
    ]

    return "\n".join(lines)


def save_report(report: str, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(report)
