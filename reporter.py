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


def render_report(
    filename: str,
    resources: List[Dict],
    findings: List[Dict],
    suppressed: List[Dict] = None,
) -> str:
    suppressed = suppressed or []
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

    finding_summary = f"{len(findings)} ({static_count} static, {ai_count} AI-identified)"
    if suppressed:
        finding_summary += f", {len(suppressed)} suppressed"

    lines = []

    # Header
    lines += [
        f"# K8s Security Analysis Report",
        f"",
        f"**File:** `{filename}`  ",
        f"**Scanned:** {now}  ",
        f"**Resources:** {', '.join(kinds)}  ",
        f"**Total findings:** {finding_summary}",
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

    # Suppressed findings
    if suppressed:
        lines += ["## Suppressed findings", ""]
        lines.append("The following findings were suppressed by `.k8s-checker-ignore.yaml`:\n")
        for f in suppressed:
            reason = f.get("suppressed_reason", "no reason given")
            sev = f.get("severity", "INFO")
            icon = SEVERITY_ICON.get(sev, "⚪")
            lines.append(f"- {icon} `{f.get('check_id')}` **{f.get('title')}** — `{f.get('context')}` *(reason: {reason})*")
        lines.append("")

    lines += [
        "---",
        f"*KubeSentinel — AI-powered Kubernetes security agent*",
    ]

    return "\n".join(lines)


def render_pr_comment(
    files_scanned: List[str],
    resources: List[Dict],
    findings: List[Dict],
    suppressed: List[Dict] = None,
    run_url: str = "",
) -> str:
    suppressed = suppressed or []
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    kinds = [r.get("kind", "Unknown") for r in resources]

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    score = (
        counts.get("CRITICAL", 0) * 10 +
        counts.get("HIGH", 0) * 5 +
        counts.get("MEDIUM", 0) * 2 +
        counts.get("LOW", 0) * 1
    )

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high = counts.get("HIGH", 0) > 0

    if has_critical:
        status_icon = "⛔"
        status_text = "BLOCKED"
        banner = f"> ⛔ **{counts['CRITICAL']} CRITICAL finding(s) must be resolved before merging.**"
    elif has_high:
        status_icon = "⚠️"
        status_text = "WARNING"
        banner = f"> ⚠️ **No CRITICAL findings, but {counts['HIGH']} HIGH severity issue(s) need attention.**"
    elif findings:
        status_icon = "🟡"
        status_text = "ADVISORY"
        banner = "> 🟡 **No CRITICAL or HIGH findings. Review MEDIUM/LOW items below.**"
    else:
        status_icon = "✅"
        status_text = "PASSED"
        banner = "> ✅ **No significant security issues found in the changed manifests.**"

    file_list = ", ".join(f"`{f}`" for f in files_scanned[:5])
    if len(files_scanned) > 5:
        file_list += f" +{len(files_scanned) - 5} more"

    static_count = sum(1 for f in findings if f.get("source") == "static")
    ai_count = sum(1 for f in findings if f.get("source") == "claude-ai")

    lines = [
        f"## 🛡 KubeSentinel · {status_icon} {status_text}",
        "",
        banner,
        "",
        f"**Scanned:** {file_list}  ",
        f"**Resources:** {', '.join(kinds) or 'none'}  ",
        f"**Findings:** {len(findings)} ({static_count} static, {ai_count} AI-identified)"
        + (f", {len(suppressed)} suppressed" if suppressed else "") + "  ",
        f"**Timestamp:** {now}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, icon in SEVERITY_ICON.items():
        lines.append(f"| {icon} {sev} | {counts.get(sev, 0)} |")

    lines += ["", f"**Risk score:** {score}"]

    if findings:
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))
        detail_lines = []
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            icon = SEVERITY_ICON.get(sev, "⚪")
            source_badge = "[AI]" if f.get("source") == "claude-ai" else "[static]"
            detail_lines += [
                f"### {i}. {icon} {f.get('title', 'Untitled')} `{source_badge}`",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Check ID** | `{f.get('check_id', 'N/A')}` |",
                f"| **Severity** | {sev} |",
                f"| **Resource** | `{f.get('context', 'N/A')}` |",
            ]
            if f.get("resource_path"):
                detail_lines.append(f"| **Path** | `{f.get('resource_path')}` |")
            detail_lines += [
                "",
                f"**What's wrong:** {f.get('detail', '')}",
                "",
                f"**How to fix:** {f.get('remediation', '')}",
                "",
            ]
            if f.get("attack_scenario"):
                detail_lines += [f"**Attack scenario:** {f.get('attack_scenario')}", ""]
            detail_lines.append("---")
            detail_lines.append("")

        lines += [
            "",
            "<details>",
            "<summary>📋 View all findings</summary>",
            "",
        ] + detail_lines + ["</details>"]

    run_link = f" · [View workflow run]({run_url})" if run_url else ""
    lines += [
        "",
        "---",
        f"*[KubeSentinel](https://github.com/jaydenaung/kubesentinel) — AI-powered Kubernetes security agent{run_link}*",
    ]

    return "\n".join(lines)


def save_report(report: str, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
