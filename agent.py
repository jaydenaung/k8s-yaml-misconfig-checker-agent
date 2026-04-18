# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
K8s YAML Misconfiguration Checker Agent by Jayden Aung

Usage:
    python agent.py <manifest.yaml>
    python agent.py samples/vulnerable.yaml
    python agent.py samples/vulnerable.yaml --output reports/result.md
"""

import sys
import os
import argparse
import json
from pathlib import Path

from analyzer import load_manifests, run_static_checks
from claude_agent import analyze_with_claude
from reporter import render_report, save_report


def main():
    parser = argparse.ArgumentParser(
        description="K8s YAML Misconfiguration Checker — AI-powered security analysis"
    )
    parser.add_argument("manifest", help="Path to Kubernetes YAML manifest file")
    parser.add_argument(
        "--output", "-o",
        help="Save report to file (e.g. reports/result.md)",
        default=None
    )
    parser.add_argument(
        "--json",
        help="Output raw JSON findings instead of formatted report",
        action="store_true"
    )
    parser.add_argument(
        "--no-ai",
        help="Run static checks only, skip Claude analysis",
        action="store_true"
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] File not found: {manifest_path}")
        sys.exit(1)

    print(f"\n  K8s Misconfiguration Checker")
    print(f"  Analyzing: {manifest_path.name}\n")

    # Step 1: Parse YAML into resource objects
    print("[1/3] Parsing manifest...")
    resources = load_manifests(manifest_path)
    print(f"      Found {len(resources)} resource(s): {[r.get('kind','Unknown') for r in resources]}")

    # Step 2: Run static rule-based checks
    print("[2/3] Running static security checks...")
    static_findings = run_static_checks(resources)
    print(f"      {len(static_findings)} finding(s) from static analysis")

    # Step 3: Claude AI analysis
    ai_findings = []
    if not args.no_ai:
        print("[3/3] Running Claude AI analysis...")
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("      [WARN] ANTHROPIC_API_KEY not set — skipping AI analysis.")
            print("             Set it with: export ANTHROPIC_API_KEY=your-key-here")
        else:
            ai_findings = analyze_with_claude(resources, static_findings, api_key)
            print(f"      Claude identified {len(ai_findings)} additional insight(s)")
    else:
        print("[3/3] Skipping AI analysis (--no-ai flag set)")

    all_findings = static_findings + ai_findings

    if args.json:
        print(json.dumps(all_findings, indent=2))
        return

    # Step 4: Render and output report
    report = render_report(manifest_path.name, resources, all_findings)
    print("\n" + "─" * 60)
    print(report)
    print("─" * 60)

    if args.output:
        save_report(report, args.output)
        print(f"\n  Report saved to: {args.output}")

    # Exit with non-zero if critical findings exist
    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    if critical:
        sys.exit(2)


if __name__ == "__main__":
    main()
