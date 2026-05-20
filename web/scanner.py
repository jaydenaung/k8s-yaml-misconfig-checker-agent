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

    return resources, findings


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
        ))
    scan.critical_count = counts.get("CRITICAL", 0)
    scan.high_count     = counts.get("HIGH", 0)
    scan.medium_count   = counts.get("MEDIUM", 0)
    scan.low_count      = counts.get("LOW", 0)
    scan.info_count     = counts.get("INFO", 0)


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
                db.add(Image(scan_id=scan.id, image_ref=img))
