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
from claude_agent import analyze_with_agent, generate_patches_for_findings, DEFAULT_MODEL
from reporter import render_report, render_pr_comment, save_report
from suppressor import load_suppressions, apply_suppressions


_STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "SKIP": "·", "MANUAL": "?", "ERROR": "!"}


def _run_cis(args) -> int:
    """Execute a CIS benchmark scan. Returns the process exit code."""
    from cis import APIRunner, Orchestrator, RunnerContext, load_benchmark
    from cis.result import Status, score as compute_score

    try:
        benchmark = load_benchmark(args.cis_version)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return 1

    kubeconfig = args.kubeconfig or os.environ.get("KUBECONFIG")
    if not args.json:
        print(f"\n  KubeSentinel — CIS Kubernetes Benchmark v{benchmark.version}")
        print(f"  Checks: {len(benchmark.checks)}  ·  Kubeconfig: {kubeconfig or 'current context'}\n")

    ctx = RunnerContext(kubeconfig_path=kubeconfig)
    orchestrator = Orchestrator(runners=[APIRunner()])
    results = orchestrator.run_benchmark(benchmark, ctx)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, default=str))
        return _cis_exit_code(results)

    # Group + render a compact text report.
    sections: dict = {}
    for r in results:
        sections.setdefault(r.section, []).append(r)

    for section, controls in sorted(sections.items()):
        print(f"── {section} " + "─" * max(1, 60 - len(section)))
        for r in controls:
            status_str = r.status.value if hasattr(r.status, "value") else str(r.status)
            icon = _STATUS_ICON.get(status_str, "?")
            sev = f" [{r.severity}]" if r.status == Status.FAIL and r.severity else ""
            print(f"  {icon} {r.control_id}  {r.title}{sev}")
            if r.status == Status.FAIL and r.actual_value is not None:
                print(f"        expected: {r.expected_value}   observed: {r.actual_value}")
            elif r.status == Status.SKIP and r.evidence_source:
                print(f"        skipped: {r.evidence_source}")
            elif r.status == Status.ERROR and r.error:
                print(f"        error: {r.error}")
        print()

    score = compute_score(results)
    counts = {s.value: 0 for s in Status}
    for r in results:
        s = r.status.value if hasattr(r.status, "value") else str(r.status)
        counts[s] = counts.get(s, 0) + 1
    print("─" * 64)
    print(f"  Score: {score}%   "
          f"PASS={counts.get('PASS',0)}  FAIL={counts.get('FAIL',0)}  "
          f"SKIP={counts.get('SKIP',0)}  MANUAL={counts.get('MANUAL',0)}  "
          f"ERROR={counts.get('ERROR',0)}")
    print("─" * 64)

    if args.output:
        save_report("\n".join([
            f"# CIS Kubernetes Benchmark v{benchmark.version}",
            f"Score: {score}%",
            "",
            *[f"- [{(r.status.value if hasattr(r.status,'value') else r.status)}] {r.control_id} — {r.title}"
              for r in results],
        ]), args.output)
        print(f"\n  Report saved to: {args.output}")

    return _cis_exit_code(results)


def _cis_exit_code(results) -> int:
    """Exit 2 if any CRITICAL/HIGH FAIL exists, 0 otherwise."""
    from cis.result import Status
    for r in results:
        if r.status == Status.FAIL and r.severity in ("CRITICAL", "HIGH"):
            return 2
    return 0


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
    parser.add_argument(
        "--patch",
        help="Generate AI-corrected YAML patches for every finding (premium feature, requires ANTHROPIC_API_KEY)",
        action="store_true",
    )
    parser.add_argument(
        "--cis",
        help="Run a CIS Kubernetes Benchmark scan against the current kubectl context",
        action="store_true",
    )
    parser.add_argument(
        "--kubeconfig",
        help="Path to a kubeconfig file (CIS mode only). Defaults to the KUBECONFIG env var.",
        default=None,
    )
    parser.add_argument(
        "--cis-version",
        help="CIS benchmark version (default: 1.9)",
        default="1.9",
    )
    args = parser.parse_args()

    if args.cis:
        sys.exit(_run_cis(args))

    if not args.manifest and not args.files:
        parser.error("Provide a manifest path, --files FILE [FILE ...], or --cis")
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

        if args.patch and not args.no_ai:
            api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                print("[patch] Generating AI patches for findings...")
                model = args.model or os.environ.get("K8S_CHECKER_MODEL")
                findings = generate_patches_for_findings(findings, api_key, verbose=True, model=model)
                patched = sum(1 for f in findings if f.get("suggested_patch"))
                print(f"        {patched} patch(es) generated")

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

    if args.patch:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("[WARN] --patch requires ANTHROPIC_API_KEY — skipping patch generation")
        else:
            print("\n[patch] Generating AI patches for findings...")
            model = args.model or os.environ.get("K8S_CHECKER_MODEL")
            findings = generate_patches_for_findings(findings, api_key, verbose=True, model=model)
            patched = sum(1 for f in findings if f.get("suggested_patch"))
            print(f"        {patched} patch(es) generated")

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
