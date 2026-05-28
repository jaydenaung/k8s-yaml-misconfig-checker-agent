# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/parsers/default_sa.py — CIS 5.1.5 / 5.1.6 family checks on default
ServiceAccounts.

The check is "the default SA must not auto-mount its token in every
namespace". We return 'true' if any non-system namespace has a default SA
with automountServiceAccountToken != false, 'false' otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from cis.parsers.base import ParserError, ParserOutput


_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


def _kubectl_get_json(
    cmd_extra: List[str],
    kubeconfig_path: Optional[str],
    timeout: int = 30,
) -> Dict[str, Any]:
    cmd = ["kubectl", "get"] + cmd_extra + ["-o", "json"]
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


def parse_default_sa_automount(params: Dict[str, Any], ctx) -> ParserOutput:
    """
    Returns 'true' if any default SA in a non-system namespace permits
    auto-mounted tokens (i.e. automountServiceAccountToken != false).
    Returns 'false' if every default SA explicitly disables auto-mount.

    audit:
      type: default_sa_automount
      include_system_namespaces: false   # default
    """
    include_system = bool(params.get("include_system_namespaces", False))
    kubeconfig_path = getattr(ctx, "kubeconfig_path", None)

    data = _kubectl_get_json(["serviceaccounts", "-A"], kubeconfig_path)
    offenders: List[str] = []

    for sa in data.get("items", []):
        meta = sa.get("metadata") or {}
        if meta.get("name") != "default":
            continue
        ns = meta.get("namespace") or "default"
        if not include_system and ns in _SYSTEM_NAMESPACES:
            continue
        if sa.get("automountServiceAccountToken") is not False:
            offenders.append(ns)

    any_offender = bool(offenders)
    sample = ", ".join(offenders[:5])
    suffix = f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""
    evidence = (
        f"{len(offenders)} namespaces have default SA with auto-mount enabled"
        + (f" — {sample}{suffix}" if sample else "")
    )

    return ParserOutput(
        actual_value="true" if any_offender else "false",
        evidence_source=evidence,
    )
