# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/scanner.py — Background scan execution for both manifests and clusters
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from analyzer import load_manifests, run_static_checks
from web.database import Cluster, Finding, Image, Manifest, Scan, get_db

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def run_patch_generation(scan_id: int) -> None:
    """Post-scan patch generation — reads existing findings, calls Claude, saves patches."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.patches_status = "generating"
        db.commit()

        db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        findings_data = [
            {
                "check_id":    f.check_id,
                "context":     f.context,
                "title":       f.title,
                "severity":    f.severity,
                "detail":      f.detail,
                "remediation": f.remediation,
                "source":      f.source,
                "suggested_patch":   f.suggested_patch,
                "patch_explanation": f.patch_explanation,
            }
            for f in db_findings
        ]

        try:
            from claude_agent import generate_patches_for_findings
            patched = generate_patches_for_findings(findings_data, api_key)

            for pf in patched:
                if pf.get("suggested_patch"):
                    for dbf in db_findings:
                        if dbf.check_id == pf["check_id"] and dbf.context == pf["context"]:
                            dbf.suggested_patch   = pf["suggested_patch"]
                            dbf.patch_explanation = pf.get("patch_explanation")
                            break

            scan.patches_status = "done"
            db.commit()

        except Exception as exc:
            scan.patches_status = "failed"
            db.commit()
            raise exc


def run_scan(scan_id: int) -> None:
    """Execute a scan and persist all findings. Called as a BackgroundTask."""
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        try:
            if scan.scan_type == "manifest":
                _run_manifest_scan(db, scan)
            else:
                _run_cluster_scan(db, scan)
        except Exception as exc:
            scan.status = "failed"
            scan.error_message = str(exc)[:1000]
            scan.completed_at = datetime.utcnow()
            db.commit()


# ── Manifest scan ─────────────────────────────────────────────────────────────

def _run_manifest_scan(db, scan: Scan) -> None:
    manifest = db.query(Manifest).filter(Manifest.id == scan.target_id).first()
    if not manifest:
        scan.status = "failed"
        scan.error_message = "Manifest record not found"
        db.commit()
        return

    file_path = Path(manifest.file_path)
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if scan.scan_mode == "ai" and api_key:
        from claude_agent import analyze_with_agent
        resources, findings = analyze_with_agent(file_path, api_key, verbose=False)
    else:
        resources = load_manifests(file_path)
        findings = run_static_checks(resources)
        for f in findings:
            f.setdefault("source", "static")

    _persist_findings(db, scan, findings)
    _extract_images(db, scan, resources)
    scan.status = "done"
    scan.completed_at = datetime.utcnow()
    db.commit()


# ── Cluster scan ──────────────────────────────────────────────────────────────

def _run_cluster_scan(db, scan: Scan) -> None:
    cluster = db.query(Cluster).filter(Cluster.id == scan.target_id).first()
    if not cluster:
        scan.status = "failed"
        scan.error_message = "Cluster record not found"
        db.commit()
        return

    kubeconfig_path = Path(cluster.kubeconfig_path)
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if scan.scan_mode == "ai" and api_key:
        from claude_agent import analyze_cluster_with_agent
        resources, findings = analyze_cluster_with_agent(
            cluster.name, kubeconfig_path, api_key, verbose=False
        )
    else:
        resources, findings = _cluster_static_checks(kubeconfig_path)

    _persist_findings(db, scan, findings)
    cluster.last_scanned_at = datetime.utcnow()
    scan.status = "done"
    scan.completed_at = datetime.utcnow()
    db.commit()


def _cluster_static_checks(kubeconfig_path: Path) -> Tuple[List[Dict], List[Dict]]:
    """kubectl-based static checks — no AI required."""
    env = {**os.environ, "KUBECONFIG": str(kubeconfig_path)}
    resources: List[Dict] = []
    findings: List[Dict] = []

    def kubectl(resource_type: str, all_namespaces: bool = False):
        cmd = ["kubectl", "get", resource_type, "-o", "json"]
        if all_namespaces:
            cmd.append("-A")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
            if r.returncode == 0:
                return json.loads(r.stdout)
        except Exception:
            pass
        return None

    def mk(check_id, severity, ctx, title, detail, remediation, path=""):
        return {"source": "static", "check_id": check_id, "severity": severity,
                "context": ctx, "title": title, "detail": detail,
                "remediation": remediation, "resource_path": path}

    # Pods
    data = kubectl("pods", all_namespaces=True)
    if data:
        for pod in data.get("items", []):
            spec = pod.get("spec", {})
            ns = pod["metadata"].get("namespace", "default")
            name = pod["metadata"]["name"]
            ctx = f"Pod/{name} ({ns})"
            resources.append(pod)
            if spec.get("hostPID"):
                findings.append(mk("K8S-002", "CRITICAL", ctx, "hostPID enabled",
                    "Pod shares host PID namespace.", "Set hostPID: false.", "spec.hostPID"))
            if spec.get("hostIPC"):
                findings.append(mk("K8S-002", "CRITICAL", ctx, "hostIPC enabled",
                    "Pod shares host IPC namespace.", "Set hostIPC: false.", "spec.hostIPC"))
            if spec.get("hostNetwork"):
                findings.append(mk("K8S-002", "HIGH", ctx, "hostNetwork enabled",
                    "Pod shares host network namespace.", "Set hostNetwork: false.", "spec.hostNetwork"))
            for c in spec.get("containers", []):
                sc = c.get("securityContext", {})
                cname = c.get("name", "?")
                if sc.get("privileged"):
                    findings.append(mk("K8S-001", "CRITICAL", ctx,
                        f"Privileged container: {cname}",
                        f"Container {cname} runs privileged=true — full host access.",
                        "Set securityContext.privileged: false."))
                if sc.get("runAsUser") == 0:
                    findings.append(mk("K8S-003", "HIGH", ctx,
                        f"Root container: {cname}",
                        f"Container {cname} runs as UID 0.",
                        "Set runAsUser to a non-zero UID and runAsNonRoot: true."))

    # Cluster-admin bindings
    data = kubectl("clusterrolebindings")
    if data:
        for crb in data.get("items", []):
            name = crb["metadata"]["name"]
            if crb.get("roleRef", {}).get("name") == "cluster-admin":
                for s in crb.get("subjects", []):
                    if s.get("kind") == "ServiceAccount":
                        findings.append(mk("K8S-014", "CRITICAL",
                            f"ClusterRoleBinding/{name}",
                            "Service account bound to cluster-admin",
                            f"ServiceAccount '{s.get('name')}' in namespace "
                            f"'{s.get('namespace')}' has cluster-admin rights.",
                            "Restrict to minimum required RBAC permissions."))

    # Namespaces without NetworkPolicies
    np_data = kubectl("networkpolicies", all_namespaces=True)
    covered = set()
    if np_data:
        for np in np_data.get("items", []):
            covered.add(np["metadata"].get("namespace"))
    ns_data = kubectl("namespaces")
    system_ns = {"kube-system", "kube-public", "kube-node-lease"}
    if ns_data:
        for ns_item in ns_data.get("items", []):
            ns_name = ns_item["metadata"]["name"]
            if ns_name not in system_ns and ns_name not in covered:
                findings.append(mk("K8S-010", "MEDIUM",
                    f"Namespace/{ns_name}",
                    "No NetworkPolicy in namespace",
                    f"Namespace '{ns_name}' has no NetworkPolicy — all pod traffic is allowed.",
                    "Add a default-deny NetworkPolicy and allow only required traffic."))

    # SA permission probing
    findings.extend(_sa_probe_checks(kubeconfig_path, env))

    # Compound risk correlation
    findings.extend(_correlate_risks(findings, kubeconfig_path, env))

    return resources, findings


def _sa_probe_checks(kubeconfig_path: Path, env: dict) -> List[Dict]:
    """Probe service account permissions via kubectl auth can-i --as impersonation."""
    _SENSITIVE = [
        ("get",    "secrets"),
        ("list",   "secrets"),
        ("get",    "configmaps"),
        ("list",   "configmaps"),
        ("create", "pods"),
        ("delete", "pods"),
        ("create", "clusterrolebindings"),
        ("delete", "clusterrolebindings"),
    ]

    def can_i(verb: str, resource: str, as_flag: str, ns: str) -> bool:
        try:
            r = subprocess.run(
                ["kubectl", "auth", "can-i", verb, resource, f"--as={as_flag}", "-n", ns],
                capture_output=True, text=True, timeout=10, env=env,
            )
            return r.returncode == 0 and r.stdout.strip() == "yes"
        except Exception:
            return False

    # Discover pods and their service accounts
    try:
        r = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if r.returncode != 0:
            return []
        pod_data = json.loads(r.stdout)
    except Exception:
        return []

    # Build (namespace, sa) → [pod names]
    sa_pods: Dict[Tuple[str, str], List[str]] = {}
    for pod in pod_data.get("items", []):
        spec = pod.get("spec", {})
        if spec.get("automountServiceAccountToken") is False:
            continue
        ns   = pod["metadata"].get("namespace", "default")
        name = pod["metadata"]["name"]
        sa   = spec.get("serviceAccountName", "default")
        sa_pods.setdefault((ns, sa), []).append(name)

    findings: List[Dict] = []
    for (ns, sa), pods in sa_pods.items():
        as_flag   = f"system:serviceaccount:{ns}:{sa}"
        confirmed = [
            f"{v} {r}" for v, r in _SENSITIVE if can_i(v, r, as_flag, ns)
        ]
        if not confirmed:
            continue

        has_secrets = any("secrets" in c for c in confirmed)
        severity    = "CRITICAL" if (has_secrets or "create clusterrolebindings" in confirmed) else "HIGH"
        pod_list    = ", ".join(pods[:5]) + ("…" if len(pods) > 5 else "")

        findings.append({
            "source":     "sa-probe",
            "check_id":   "SAP-001",
            "severity":   severity,
            "context":    f"ServiceAccount/{sa} ({ns})",
            "title":      f"SA '{sa}' has runtime-confirmed {'secret' if has_secrets else 'elevated'} access",
            "detail":     (
                f"ServiceAccount '{sa}' in namespace '{ns}' is mounted on: {pod_list}. "
                f"Runtime probe confirmed it can: {', '.join(confirmed)}."
            ),
            "remediation": (
                "Set automountServiceAccountToken: false on the pod spec and create a "
                "dedicated SA with least-privilege RBAC scoped to specific resource names."
            ),
            "resource_path":   "spec.serviceAccountName",
            "attack_scenario": (
                f"An attacker who compromises any pod using SA '{sa}' can immediately "
                f"call the Kubernetes API to: {', '.join(confirmed)}."
            ),
        })

    return findings


def _correlate_risks(findings: List[Dict], kubeconfig_path: Path, env: dict) -> List[Dict]:
    """Correlate CVE + misconfiguration + RBAC + network signals into compound findings."""
    # ── Collect running pods ────────────────────────────────────────────────
    try:
        r = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if r.returncode != 0:
            return []
        pods = json.loads(r.stdout).get("items", [])
    except Exception:
        return []

    # ── Index existing findings ─────────────────────────────────────────────
    misconfig_contexts: set = set()   # pod contexts with CRITICAL/HIGH static findings
    sa_danger: set = set()            # SA names confirmed dangerous by sa-probe
    no_netpol_ns: set = set()         # namespaces without NetworkPolicy

    for f in findings:
        ctx = f.get("context", "")
        sev = f.get("severity", "")
        src = f.get("source", "")
        if src == "sa-probe":
            # "ServiceAccount/sa-name (ns)" → extract sa name
            sa_name = ctx.split("/")[1].split(" ")[0] if "/" in ctx else ctx
            sa_danger.add(sa_name)
        elif src in ("static", "claude-ai") and sev in ("CRITICAL", "HIGH"):
            misconfig_contexts.add(ctx)
        if f.get("check_id") == "K8S-010":
            ns = ctx.replace("Namespace/", "").strip()
            no_netpol_ns.add(ns)

    # ── Scan unique images with Trivy ───────────────────────────────────────
    unique_images: set = set()
    for pod in pods:
        for c in pod.get("spec", {}).get("containers", []):
            img = c.get("image")
            if img:
                unique_images.add(img)

    image_cves: Dict[str, Dict] = {}
    for img in unique_images:
        image_cves[img] = _trivy_scan(img)

    # ── Correlate per pod ───────────────────────────────────────────────────
    compound: List[Dict] = []
    seen_pods: set = set()

    for pod in pods:
        ns    = pod["metadata"].get("namespace", "default")
        name  = pod["metadata"]["name"]
        spec  = pod.get("spec", {})
        sa    = spec.get("serviceAccountName", "default")
        ctx   = f"Pod/{name} ({ns})"

        if ctx in seen_pods:
            continue
        seen_pods.add(ctx)

        images = [c.get("image") for c in spec.get("containers", []) if c.get("image")]

        # Gather signals
        signals:        List[str] = []
        signal_details: List[str] = []
        chain:          List[str] = []

        # CVE signal
        worst_cves = {}
        for img in images:
            cves = image_cves.get(img, {})
            if cves.get("critical", 0) > 0 or cves.get("high", 0) > 5:
                if cves.get("critical", 0) > worst_cves.get("critical", 0):
                    worst_cves = {**cves, "image": img}
        if worst_cves:
            signals.append("cve")
            signal_details.append(
                f"Image {worst_cves['image']}: "
                f"{worst_cves.get('critical',0)} critical CVEs, "
                f"{worst_cves.get('high',0)} high CVEs"
            )
            chain.append(f"exploit CVE in {worst_cves['image']}")

        # Misconfiguration signal
        if ctx in misconfig_contexts:
            signals.append("misconfiguration")
            signal_details.append("Pod has CRITICAL/HIGH misconfigurations (privileged, root, hostPID…)")
            chain.append("leverage misconfiguration for container escape / host access")

        # RBAC signal
        if sa in sa_danger:
            signals.append("rbac")
            signal_details.append(f"SA '{sa}' has runtime-confirmed dangerous API access")
            chain.append("use mounted SA token to access Kubernetes secrets via API")

        # Network exposure signal
        if ns in no_netpol_ns:
            signals.append("network")
            signal_details.append(f"Namespace '{ns}' has no NetworkPolicy — unrestricted pod traffic")
            chain.append("reach pod from other namespaces or internet (no NetworkPolicy)")

        if len(signals) < 2:
            continue

        has_cve   = "cve" in signals
        has_rbac  = "rbac" in signals
        has_misc  = "misconfiguration" in signals
        severity  = "CRITICAL" if (has_cve and has_rbac) or (has_cve and has_misc and len(signals) >= 3) else "HIGH"
        check_id  = f"CMP-00{min(len(signals), 4)}"

        compound.append({
            "source":     "compound",
            "check_id":   check_id,
            "severity":   severity,
            "context":    ctx,
            "title":      f"Compound risk ({len(signals)} signals): {' + '.join(signals)}",
            "detail":     (
                f"This pod has {len(signals)} correlated risk signals:\n"
                + "\n".join(f"• {d}" for d in signal_details)
            ),
            "remediation": (
                "Prioritise by exploitability: "
                "1) Patch or replace the vulnerable image. "
                "2) Remove misconfiguration (privileged:false, runAsNonRoot:true). "
                "3) Set automountServiceAccountToken:false and tighten RBAC. "
                "4) Add a default-deny NetworkPolicy."
            ),
            "attack_scenario": "Attacker chain: " + " → ".join(chain) + ".",
            "resource_path": "",
        })

    return compound


# ── Persistence helpers ───────────────────────────────────────────────────────

def _persist_findings(db, scan: Scan, findings: List[Dict]) -> None:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        db.add(Finding(
            scan_id=scan.id,
            check_id=f.get("check_id"),
            severity=sev,
            source=f.get("source"),
            context=f.get("context"),
            title=f.get("title"),
            detail=f.get("detail"),
            remediation=f.get("remediation"),
            resource_path=f.get("resource_path"),
            attack_scenario=f.get("attack_scenario"),
            telco_relevance=f.get("telco_relevance"),
            suggested_patch=f.get("suggested_patch"),
            patch_explanation=f.get("patch_explanation"),
        ))
    scan.critical_count = counts.get("CRITICAL", 0)
    scan.high_count     = counts.get("HIGH", 0)
    scan.medium_count   = counts.get("MEDIUM", 0)
    scan.low_count      = counts.get("LOW", 0)
    scan.info_count     = counts.get("INFO", 0)


def _trivy_scan(image_ref: str) -> Dict:
    """Run Trivy against a single image. Returns CVE counts or empty dict if unavailable."""
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", "--no-progress", image_ref],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return {}
        data = json.loads(result.stdout)
        counts: Dict[str, int] = {}
        top: Dict[str, List] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                sev = v.get("Severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
                if sev in top and len(top[sev]) < 5:
                    top[sev].append({
                        "id":      v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "fixed":   v.get("FixedVersion"),
                    })
        details = {k.lower(): v for k, v in top.items() if v}
        return {
            "critical": counts.get("CRITICAL", 0),
            "high":     counts.get("HIGH", 0),
            "medium":   counts.get("MEDIUM", 0),
            "low":      counts.get("LOW", 0),
            "total":    sum(counts.values()),
            "details":  json.dumps(details),
        }
    except FileNotFoundError:
        return {}  # Trivy not installed — skip silently
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return {}


def _extract_images(db, scan: Scan, resources: List[Dict]) -> None:
    seen: set = set()
    for r in resources:
        spec = r.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        all_containers = (
            pod_spec.get("containers", []) +
            pod_spec.get("initContainers", [])
        )
        for c in all_containers:
            img = c.get("image")
            if img and img not in seen:
                seen.add(img)
                cves = _trivy_scan(img)
                db.add(Image(
                    scan_id=scan.id,
                    image_ref=img,
                    critical_cves=cves.get("critical", 0),
                    high_cves=cves.get("high", 0),
                    medium_cves=cves.get("medium", 0),
                    low_cves=cves.get("low", 0),
                    total_cves=cves.get("total", 0),
                    cve_details=cves.get("details"),
                ))
