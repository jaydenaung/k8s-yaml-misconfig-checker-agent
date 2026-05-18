# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
KubeSentinel — AI-powered Kubernetes Security Agent by Jayden Aung

Usage:
    python agent.py <manifest.yaml>
    python agent.py <directory/>
    python agent.py <helm-chart/>
    python agent.py samples/vulnerable.yaml --output reports/result.md
    python agent.py samples/vulnerable.yaml --no-ai
"""

import sys
import os
import argparse
import json
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from analyzer import load_manifests, run_static_checks
from claude_agent import analyze_with_agent, DEFAULT_MODEL
from reporter import render_report, save_report
from suppressor import load_suppressions, apply_suppressions


def main():
    parser = argparse.ArgumentParser(
        description="KubeSentinel — AI-powered Kubernetes security agent"
    )
    parser.add_argument(
        "manifest",
        help="Path to a Kubernetes YAML file, a directory of manifests, or a Helm chart directory"
    )
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
    parser.add_argument(
        "--model",
        help=f"Claude model to use (default: {DEFAULT_MODEL}, or set K8S_CHECKER_MODEL env var)",
        default=None,
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] Path not found: {manifest_path}")
        sys.exit(1)

    is_helm = manifest_path.is_dir() and (manifest_path / "Chart.yaml").exists()
    is_dir  = manifest_path.is_dir() and not is_helm

    label = "Helm chart" if is_helm else ("directory" if is_dir else "manifest")
    print(f"\n  KubeSentinel — AI-powered Kubernetes Security Agent")
    print(f"  Analyzing {label}: {manifest_path}\n")

    # Load suppression rules from .k8s-checker-ignore.yaml
    suppressions = load_suppressions(manifest_path if manifest_path.is_dir() else manifest_path.parent)
    if suppressions:
        print(f"  Suppression rules loaded: {len(suppressions)} rule(s)\n")

    if args.no_ai:
        print("[1/2] Loading manifests...")
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
            print("        Or add it to a .env file in this directory.")
            sys.exit(1)

        model = args.model or os.environ.get("K8S_CHECKER_MODEL")
        print("[agent] Claude is driving the analysis...\n")
        resources, findings = analyze_with_agent(
            manifest_path, api_key, verbose=True, model=model
        )
        static_count = sum(1 for f in findings if f.get("source") == "static")
        ai_count     = sum(1 for f in findings if f.get("source") == "claude-ai")
        print(f"\n      {len(findings)} total finding(s)  "
              f"({static_count} static, {ai_count} AI-identified)")

    # Apply suppressions
    findings, suppressed = apply_suppressions(findings, suppressions)
    if suppressed:
        print(f"      {len(suppressed)} finding(s) suppressed by .k8s-checker-ignore.yaml")

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    report = render_report(manifest_path.name, resources, findings, suppressed=suppressed)
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
