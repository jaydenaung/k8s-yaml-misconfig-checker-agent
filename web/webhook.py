# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/webhook.py — SIEM webhook dispatcher

Fires a POST after every completed scan to a configurable endpoint.
Supports generic JSON (Elastic, Datadog, custom) and Splunk HEC format.

Configuration (env vars):
  WEBHOOK_URL     — endpoint to POST to (required to enable)
  WEBHOOK_TOKEN   — auth token; sent as "Bearer <token>" or "Splunk <token>"
  WEBHOOK_FORMAT  — "json" (default) or "splunk"

Errors are silently logged — a broken webhook never affects scan results.
"""

import json
import os
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from web.database import Finding, Scan, get_db

_SUPPORTED_FORMATS = ("json", "splunk")


def _build_payload(scan: Scan, findings: list) -> Dict:
    return {
        "source":       "kubesentinel",
        "scan_id":      scan.id,
        "scan_type":    scan.scan_type,
        "target":       scan.target_name,
        "scan_mode":    scan.scan_mode,
        "triggered_by": scan.triggered_by,
        "status":       scan.status,
        "started_at":   scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "critical": scan.critical_count or 0,
            "high":     scan.high_count or 0,
            "medium":   scan.medium_count or 0,
            "low":      scan.low_count or 0,
            "total":    (scan.critical_count or 0) + (scan.high_count or 0)
                        + (scan.medium_count or 0) + (scan.low_count or 0),
        },
        "findings": [
            {
                "check_id":       f.check_id,
                "severity":       f.severity,
                "source":         f.source,
                "context":        f.context,
                "title":          f.title,
                "detail":         f.detail,
                "remediation":    f.remediation,
                "resource_path":  f.resource_path,
                "attack_scenario": f.attack_scenario,
            }
            for f in findings
        ],
    }


def dispatch(scan_id: int) -> None:
    """POST scan results to the configured webhook. No-op if WEBHOOK_URL is unset."""
    url = os.environ.get("WEBHOOK_URL", "").strip()
    if not url:
        return

    token  = os.environ.get("WEBHOOK_TOKEN", "").strip()
    fmt    = os.environ.get("WEBHOOK_FORMAT", "json").lower()
    if fmt not in _SUPPORTED_FORMATS:
        fmt = "json"

    try:
        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            payload = _build_payload(scan, findings)
            db.expunge_all()

        if fmt == "splunk":
            body       = json.dumps({"time": int(time.time()), "sourcetype": "kubesentinel:scan", "event": payload})
            auth_value = f"Splunk {token}" if token else None
        else:
            body       = json.dumps(payload)
            auth_value = f"Bearer {token}" if token else None

        req = urllib.request.Request(
            url,
            data=body.encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if auth_value:
            req.add_header("Authorization", auth_value)

        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()

    except Exception as exc:
        print(f"[webhook] dispatch failed for scan {scan_id}: {exc}")
