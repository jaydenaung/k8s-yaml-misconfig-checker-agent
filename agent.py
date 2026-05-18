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
    python agent.py samples/vulnerable.yaml --no-ai
"""

import sys
import os
import argparse
import json
from pathlib import Path

from analyzer import load_manifests, run_static_checks
from claude_agent import analyze_with_agent
from reporter import render_report, save_report


def main():
    parser = argparse.ArgumentParser(
        description="K8s YAML Misconfiguration Checker — AI security agent"
    )
    parser.add_argument("manifest", help="Path to Kubernetes YAML manifest file")
    parser.add_argument(
        "--output", "-o",
        help="Save report to file (e.g. reports/result.md)",
        default=None,
    )
    parser.add_argument(
        "--json",
        help="Output raw JSON findings instead of a formatted report",
        action="store_true",
    )
    parser.add_argument(
        "--no-ai",
        help="Run static checks only, skip the Claude agent",
        action="store_true",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] File not found: {manifest_path}")
        sys.exit(1)

    print(f"\n  K8s Misconfiguration Checker — Agent Mode")
    print(f"  Analyzing: {manifest_path.name}\n")

    if args.no_ai:
        # Static-only path
        print("[1/2] Parsing manifest...")
        resources = load_manifests(manifest_path)
        print(f"      Found {len(resources)} resource(s): {[r.get('kind', 'Unknown') for r in resources]}")

        print("[2/2] Running static security checks...")
        findings = run_static_checks(resources)
        print(f"      {len(findings)} finding(s) from static analysis")

    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("[ERROR] ANTHROPIC_API_KEY not set.")
            print("        Set it with: export ANTHROPIC_API_KEY=your-key-here")
            sys.exit(1)

        print("[agent] Claude is driving the analysis...\n")
        resources, findings = analyze_with_agent(manifest_path, api_key, verbose=True)
        static_count = sum(1 for f in findings if f.get("source") == "static")
        ai_count     = sum(1 for f in findings if f.get("source") == "claude-ai")
        print(f"\n      {len(findings)} total finding(s)  "
              f"({static_count} static, {ai_count} AI-identified)")

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    report = render_report(manifest_path.name, resources, findings)
    print("\n" + "─" * 60)
    print(report)
    print("─" * 60)

    if args.output:
        save_report(report, args.output)
        print(f"\n  Report saved to: {args.output}")

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    if critical:
        sys.exit(2)


if __name__ == "__main__":
    main()
