# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""
suppressor.py — Load and apply .k8s-checker-ignore.yaml suppression rules
"""

import yaml
from pathlib import Path
from typing import Dict, List, Tuple

IGNORE_FILE = ".k8s-checker-ignore.yaml"


def load_suppressions(search_path: Path = Path(".")) -> List[Dict]:
    """Search for .k8s-checker-ignore.yaml next to the manifest, then in cwd."""
    for candidate in [search_path / IGNORE_FILE, Path(IGNORE_FILE)]:
        if candidate.exists():
            with open(candidate) as f:
                data = yaml.safe_load(f) or {}
            return data.get("suppress", [])
    return []


def apply_suppressions(
    findings: List[Dict],
    suppressions: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """
    Split findings into (active, suppressed).
    A suppression rule matches when check_id matches AND resource matches (if specified).
    """
    if not suppressions:
        return findings, []

    active, suppressed = [], []
    for finding in findings:
        rule = next(
            (
                r for r in suppressions
                if r.get("check_id") == finding.get("check_id")
                and ("resource" not in r or r["resource"] == finding.get("context"))
            ),
            None,
        )
        if rule:
            suppressed.append({**finding, "suppressed_reason": rule.get("reason", "")})
        else:
            active.append(finding)

    return active, suppressed
