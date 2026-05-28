# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/parsers/rbac.py — Audit RBAC bindings (CIS section 5.1).

The cluster-admin minimization check is intrinsically MANUAL in CIS, but we
still produce a structured count + the subject list so reviewers have evidence
to act on.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from cis.parsers.base import ParserError, ParserOutput


def _kubectl_get_json(
    resource: str,
    kubeconfig_path: Optional[str],
    timeout: int = 30,
) -> Dict[str, Any]:
    cmd = ["kubectl", "get", resource, "-o", "json"]
    env = dict(os.environ)
    if kubeconfig_path:
        env["KUBECONFIG"] = kubeconfig_path
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError as exc:
        raise ParserError("kubectl not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ParserError("kubectl timed out") from exc

    if result.returncode != 0:
        raise ParserError(f"kubectl failed: {result.stderr.strip()[:200]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ParserError("kubectl output was not valid JSON") from exc


_BOOTSTRAP_BINDINGS = {"cluster-admin"}      # the canonical system:masters binding
_BOOTSTRAP_SUBJECTS = {"system:masters"}     # the bootstrap group


def parse_rbac_subject_count(params: Dict[str, Any], ctx) -> ParserOutput:
    """
    Count subjects bound to a given ClusterRole, optionally excluding the
    canonical bootstrap binding so non-bootstrap usage is what gets surfaced.

    audit:
      type: rbac_subject_count
      role_ref: cluster-admin
      exclude_bootstrap: true   # skip the system:masters → cluster-admin binding
    """
    role_ref = params["role_ref"]
    exclude_bootstrap = bool(params.get("exclude_bootstrap", True))

    data = _kubectl_get_json("clusterrolebindings", getattr(ctx, "kubeconfig_path", None))
    items = data.get("items", [])

    subjects_collected: List[str] = []
    for binding in items:
        if binding.get("roleRef", {}).get("name") != role_ref:
            continue
        binding_name = binding.get("metadata", {}).get("name", "?")
        for s in binding.get("subjects") or []:
            kind = s.get("kind", "")
            name = s.get("name", "")
            ns = s.get("namespace") or ""
            if exclude_bootstrap and binding_name in _BOOTSTRAP_BINDINGS and name in _BOOTSTRAP_SUBJECTS:
                continue
            subject_id = f"{kind}/{name}" + (f"@{ns}" if ns else "")
            subjects_collected.append(f"{binding_name}->{subject_id}")

    count = len(subjects_collected)
    # Evidence shows the count plus up to 5 example subjects for human review.
    examples = ", ".join(subjects_collected[:5])
    suffix = f" (+{count - 5} more)" if count > 5 else ""
    evidence = f"ClusterRoleBindings to '{role_ref}': {count} non-bootstrap subjects"
    if examples:
        evidence += f" — {examples}{suffix}"

    return ParserOutput(
        actual_value=str(count),
        evidence_source=evidence,
    )
