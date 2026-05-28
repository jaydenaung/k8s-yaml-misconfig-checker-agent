# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/parsers/static_pod_arg.py — Extract command-line arguments from static pods
running in kube-system. Used for control-plane component checks
(kube-apiserver, kube-controller-manager, kube-scheduler, etcd).

On self-managed clusters (kubeadm), these components run as static pods and
their flags are visible in the pod spec. On managed control planes (EKS, GKE,
AKS) these pods are not visible — ParserNotApplicable is raised so the
orchestrator can mark the check SKIP rather than FAIL.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from cis.parsers.base import ParserError, ParserNotApplicable, ParserOutput


def _kubectl_get(
    resource: str,
    label_selector: str,
    namespace: str,
    kubeconfig_path: Optional[str],
    timeout: int = 30,
) -> Dict[str, Any]:
    cmd = ["kubectl", "get", resource, "-l", label_selector, "-n", namespace, "-o", "json"]
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


def _find_container(pod: Dict[str, Any], container_name: str) -> Optional[Dict[str, Any]]:
    for c in pod.get("spec", {}).get("containers", []):
        if c.get("name") == container_name:
            return c
    return None


def _arg_value(container_args: List[str], command: List[str], flag: str) -> Optional[str]:
    """
    Walk both `command` and `args` looking for `--flag=value` or
    `--flag value` patterns. Returns the value, or None if absent.

    Kubernetes static pods sometimes put the binary + flags in `command`
    rather than `args`, so we check both.
    """
    pieces: List[str] = list(command or []) + list(container_args or [])

    flag_prefix = f"{flag}="
    for i, piece in enumerate(pieces):
        if not isinstance(piece, str):
            continue
        if piece.startswith(flag_prefix):
            return piece[len(flag_prefix):]
        if piece == flag and i + 1 < len(pieces):
            return pieces[i + 1]
    return None


def _resolve_one_pod(
    params: Dict[str, Any],
    ctx,
) -> Dict[str, Any]:
    namespace = params.get("namespace", "kube-system")
    label_selector = params["label_selector"]
    kubeconfig_path = getattr(ctx, "kubeconfig_path", None)

    data = _kubectl_get("pods", label_selector, namespace, kubeconfig_path)
    items = data.get("items", [])
    if not items:
        raise ParserNotApplicable(
            f"No pods matching '{label_selector}' in '{namespace}' — "
            "likely a managed control plane or different topology."
        )
    return items[0]


def parse_static_pod_arg(params: Dict[str, Any], ctx) -> ParserOutput:
    """
    Return the value of a CLI flag on a control plane static pod.

    audit:
      type: static_pod_arg
      namespace: kube-system
      label_selector: "component=kube-apiserver"
      container: kube-apiserver
      arg: --anonymous-auth
    """
    container_name = params["container"]
    flag = params["arg"]

    pod = _resolve_one_pod(params, ctx)
    container = _find_container(pod, container_name)
    if container is None:
        raise ParserError(
            f"Container '{container_name}' not found in matched pod "
            f"'{pod.get('metadata', {}).get('name', '?')}'."
        )

    value = _arg_value(container.get("args", []), container.get("command", []), flag)
    pod_name = pod.get("metadata", {}).get("name", "?")
    return ParserOutput(
        actual_value=value,
        evidence_source=f"pod:{pod_name}/container:{container_name}/arg:{flag}",
    )


def parse_static_pod_arg_absent(params: Dict[str, Any], ctx) -> ParserOutput:
    """
    Same lookup as static_pod_arg, but the *expected* outcome is the absence
    of the flag. Returns 'present' or 'absent' so the schema can stay uniform
    with operator: equals + value: absent.
    """
    out = parse_static_pod_arg(params, ctx)
    return ParserOutput(
        actual_value="absent" if out.actual_value is None else "present",
        evidence_source=out.evidence_source,
    )
