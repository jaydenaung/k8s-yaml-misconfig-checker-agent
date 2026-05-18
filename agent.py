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

from analyzer import load_manifests, load_manifests_from_files, run_static_checks
from claude_agent import analyze_with_agent, DEFAULT_MODEL
from reporter import render_report, render_pr_comment, save_report
from suppressor import load_suppressions, apply_suppressions


def main():
    parser = argparse.ArgumentParser(
        description="KubeSentinel — AI-powered Kubernetes security agent"
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        help="Path to a Kubernetes YAML file, a directory of manifests, or a Helm chart directory",
        default=None,
    )
    parser.add_argument(
        "--files",
        nargs="+",
        metavar="FILE",
        help="Specific YAML files to scan (CI/PR mode). Provide one or more paths.",
        default=None,
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
    parser.add_argument(
        "--pr-comment",
        help="Format output as a compact GitHub PR comment (use with --output)",
        action="store_true",
    )
    args = parser.parse_args()

    if not args.manifest and not args.files:
        parser.error("Provide a manifest path or --files FILE [FILE ...]")
    if args.manifest and args.files:
        parser.error("Use either a manifest path or --files, not both")

    # ── Multi-file (CI/PR) mode ───────────────────────────────────────────────
    if args.files:
        file_paths = [Path(f) for f in args.files]
        missing = [str(f) for f in file_paths if not f.exists()]
        if missing:
            print(f"[ERROR] Files not found: {', '.join(missing)}")
            sys.exit(1)

        print(f"\n  KubeSentinel — AI-powered Kubernetes Security Agent")
        print(f"  PR scan: {len(file_paths)} file(s)\n")

        suppressions = load_suppressions(file_paths[0].parent)
        if suppressions:
            print(f"  Suppression rules loaded: {len(suppressions)} rule(s)\n")

        if args.no_ai:
            print("[1/2] Loading manifests...")
            resources = load_manifests_from_files(file_paths)
            print(f"      Found {len(resources)} resource(s)")
            print("[2/2] Running static security checks...")
            findings = run_static_checks(resources)
            print(f"      {len(findings)} finding(s) from static analysis")
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                print("[WARN] ANTHROPIC_API_KEY not set — falling back to static checks only.")
                resources = load_manifests_from_files(file_paths)
                findings = run_static_checks(resources)
                for f in findings:
                    f["source"] = "static"
            else:
                model = args.model or os.environ.get("K8S_CHECKER_MODEL")
                # Run agent on each file and aggregate
                resources = []
                findings = []
                for fp in file_paths:
                    print(f"[agent] Analyzing {fp.name} ...")
                    r, f = analyze_with_agent(fp, api_key, verbose=True, model=model)
                    resources.extend(r)
                    findings.extend(f)
                # Deduplicate by (check_id, context, title)
                seen = set()
                unique = []
                for f in findings:
                    key = (f["check_id"], f.get("context"), f.get("title"))
                    if key not in seen:
                        seen.add(key)
                        unique.append(f)
                findings = unique

        findings, suppressed = apply_suppressions(findings, suppressions)

        if args.json:
            print(json.dumps(findings, indent=2))
            return

        run_url = os.environ.get("GITHUB_SERVER_URL", "") + "/" + \
                  os.environ.get("GITHUB_REPOSITORY", "") + "/actions/runs/" + \
                  os.environ.get("GITHUB_RUN_ID", "")
        run_url = run_url if os.environ.get("GITHUB_RUN_ID") else ""

        if args.pr_comment:
            report = render_pr_comment(
                files_scanned=[str(f) for f in file_paths],
                resources=resources,
                findings=findings,
                suppressed=suppressed,
                run_url=run_url,
            )
        else:
            label = ", ".join(f.name for f in file_paths[:3])
            if len(file_paths) > 3:
                label += f" +{len(file_paths) - 3} more"
            report = render_report(label, resources, findings, suppressed=suppressed)

        if args.output:
            save_report(report, args.output)
            print(f"\n  Report saved to: {args.output}")
        else:
            print("\n" + "─" * 60)
            print(report)
            print("─" * 60)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if critical:
            sys.exit(2)
        return

    # ── Single path mode (original behavior) ─────────────────────────────────
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
