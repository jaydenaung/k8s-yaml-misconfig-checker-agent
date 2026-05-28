# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/cis_scanner.py — BackgroundTask wrapper around cis.Orchestrator.

Loads a benchmark, runs every check against the cluster identified by
Scan.target_id, persists results into the compliance_results table, and
updates the Scan row with aggregate counters and a 0-100 score.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from cis import APIRunner, Orchestrator, RunnerContext, load_benchmark
from cis.result import Status, score as compute_score
from web.database import Cluster, ComplianceResult, Scan, get_db


DEFAULT_FRAMEWORK = "cis-kubernetes-1.9"
DEFAULT_BENCHMARK_VERSION = "1.9"


def run_cis_scan(scan_id: int) -> None:
    """Execute a CIS compliance scan. Invoked as a FastAPI BackgroundTask."""
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        try:
            cluster = db.query(Cluster).filter(Cluster.id == scan.target_id).first()
            if not cluster:
                _fail(db, scan, "Cluster record not found")
                return

            framework = scan.framework or DEFAULT_FRAMEWORK
            version = framework.rsplit("-", 1)[-1] if "-" in framework else DEFAULT_BENCHMARK_VERSION
            try:
                benchmark = load_benchmark(version)
            except FileNotFoundError as exc:
                _fail(db, scan, f"Benchmark not found: {exc}")
                return

            ctx = RunnerContext(
                kubeconfig_path=cluster.kubeconfig_path,
                cluster_name=cluster.name,
            )
            orchestrator = Orchestrator(runners=[APIRunner()])
            results = orchestrator.run_benchmark(benchmark, ctx)

            _persist_results(db, scan, results)
            cluster.last_scanned_at = datetime.utcnow()
            scan.status = "done"
            scan.completed_at = datetime.utcnow()
            db.commit()

        except Exception as exc:
            _fail(db, scan, str(exc)[:1000])


def _persist_results(db, scan: Scan, results) -> None:
    """Insert ComplianceResult rows and update aggregate counters on the scan."""
    counts = {s.value: 0 for s in Status}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for r in results:
        status_str = r.status.value if hasattr(r.status, "value") else str(r.status)
        counts[status_str] = counts.get(status_str, 0) + 1
        if r.status == Status.FAIL and r.severity:
            sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1

        db.add(ComplianceResult(
            scan_id=scan.id,
            control_id=r.control_id,
            title=r.title,
            section=r.section,
            profile=r.profile,
            level=r.level,
            scored=r.scored,
            status=status_str,
            severity=r.severity,
            expected_value=r.expected_value,
            actual_value=r.actual_value,
            evidence_source=r.evidence_source,
            remediation=r.remediation,
            references=json.dumps(r.references) if r.references else None,
            duration_ms=r.duration_ms,
            error_message=r.error,
            checked_at=r.checked_at or datetime.utcnow(),
        ))

    scan.pass_count   = counts.get("PASS", 0)
    scan.fail_count   = counts.get("FAIL", 0)
    scan.skip_count   = counts.get("SKIP", 0)
    scan.manual_count = counts.get("MANUAL", 0)
    scan.compliance_score = compute_score(results)

    # Mirror severity rollup into the existing scan columns so the dashboard
    # shows a unified critical/high count regardless of scan type.
    scan.critical_count = sev_counts["CRITICAL"]
    scan.high_count     = sev_counts["HIGH"]
    scan.medium_count   = sev_counts["MEDIUM"]
    scan.low_count      = sev_counts["LOW"]
    scan.info_count     = sev_counts["INFO"]


def _fail(db, scan: Scan, message: str) -> None:
    scan.status = "failed"
    scan.error_message = message
    scan.completed_at = datetime.utcnow()
    db.commit()
