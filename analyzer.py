# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
analyzer.py — YAML parsing and static security checks by Jayden Aung

Static checks are fast, deterministic, and run without the API.
They cover the most common K8s security misconfigurations from:
  - CIS Kubernetes Benchmark
  - NSA/CISA Kubernetes Hardening Guide
  - OWASP Kubernetes Top 10
  
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any


def load_manifests(path: Path) -> List[Dict]:
    """Load and parse a YAML file that may contain multiple documents."""
    resources = []
    with open(path, "r") as f:
        docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc is not None:
            resources.append(doc)
    return resources


def run_static_checks(resources: List[Dict]) -> List[Dict]:
    """Run all static checks across all resources. Returns list of findings."""
    findings = []
    for resource in resources:
        kind = resource.get("kind", "Unknown")
        name = resource.get("metadata", {}).get("name", "unnamed")
        context = f"{kind}/{name}"

        fns = [
            check_privileged_containers,
            check_host_namespace,
            check_root_user,
            check_capabilities,
            check_read_only_root_fs,
            check_resource_limits,
            check_image_tag,
            check_service_account,
            check_host_path_volumes,
            check_network_policy,
            check_secrets_in_env,
            check_liveness_readiness,
            check_security_context,
            check_rbac_wildcard,
        ]

        for fn in fns:
            result = fn(resource, context)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

    return findings


# ─────────────────────────────────────────────
# Individual check functions
# Each returns None (pass) or a finding dict
# ─────────────────────────────────────────────

def _finding(check_id, severity, context, title, detail, remediation, resource_path=""):
    return {
        "source": "static",
        "check_id": check_id,
        "severity": severity,
        "context": context,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "resource_path": resource_path,
    }


def _get_containers(resource: Dict) -> List[Dict]:
    """Extract all containers (including initContainers) from a resource."""
    spec = resource.get("spec", {})
    # Handle Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob
    template_spec = spec.get("template", {}).get("spec", spec)
    containers = template_spec.get("containers", [])
    init_containers = template_spec.get("initContainers", [])
    return containers + init_containers


def check_privileged_containers(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        if sc.get("privileged") is True:
            findings.append(_finding(
                "K8S-001", "CRITICAL", context,
                f"Privileged container: {c.get('name')}",
                "Container runs with privileged=true, granting full host access.",
                "Set securityContext.privileged: false or remove the field.",
                f"spec.containers[{c.get('name')}].securityContext.privileged"
            ))
    return findings


def check_host_namespace(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    for field, label in [("hostPID", "hostPID"), ("hostIPC", "hostIPC"), ("hostNetwork", "hostNetwork")]:
        if template_spec.get(field) is True:
            sev = "CRITICAL" if field in ("hostPID", "hostIPC") else "HIGH"
            findings.append(_finding(
                "K8S-002", sev, context,
                f"{label} enabled on pod spec",
                f"{label}: true shares the host's {field.replace('host','')} namespace with the container.",
                f"Set spec.{field}: false or remove it.",
                f"spec.{field}"
            ))
    return findings


def check_root_user(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        run_as = sc.get("runAsUser")
        run_as_non_root = sc.get("runAsNonRoot")
        if run_as == 0:
            findings.append(_finding(
                "K8S-003", "HIGH", context,
                f"Container runs as root (UID 0): {c.get('name')}",
                "runAsUser: 0 explicitly runs the container as root.",
                "Set runAsUser to a non-zero UID (e.g., 1000) and runAsNonRoot: true.",
                f"spec.containers[{c.get('name')}].securityContext.runAsUser"
            ))
        elif run_as_non_root is False:
            findings.append(_finding(
                "K8S-003", "MEDIUM", context,
                f"runAsNonRoot explicitly disabled: {c.get('name')}",
                "runAsNonRoot: false allows the container to run as root.",
                "Set runAsNonRoot: true.",
                f"spec.containers[{c.get('name')}].securityContext.runAsNonRoot"
            ))
    return findings


def check_capabilities(resource, context):
    findings = []
    dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "ALL"}
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {})
        added = set(caps.get("add", []))
        dangerous = added & dangerous_caps
        if dangerous:
            findings.append(_finding(
                "K8S-004", "HIGH", context,
                f"Dangerous capabilities added: {c.get('name')}",
                f"Capabilities {dangerous} are added, granting elevated kernel privileges.",
                "Drop all capabilities and only add the minimum required. Use drop: [ALL] and add only what's needed.",
                f"spec.containers[{c.get('name')}].securityContext.capabilities.add"
            ))
        if "ALL" in added:
            findings.append(_finding(
                "K8S-004", "CRITICAL", context,
                f"ALL capabilities added: {c.get('name')}",
                "capabilities.add: [ALL] grants every Linux capability to the container.",
                "Replace with the specific capabilities the application actually needs.",
                f"spec.containers[{c.get('name')}].securityContext.capabilities.add"
            ))
    return findings


def check_read_only_root_fs(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(_finding(
                "K8S-005", "MEDIUM", context,
                f"Writable root filesystem: {c.get('name')}",
                "readOnlyRootFilesystem is not set to true. A writable root FS makes exploitation easier.",
                "Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
                f"spec.containers[{c.get('name')}].securityContext.readOnlyRootFilesystem"
            ))
    return findings


def check_resource_limits(resource, context):
    findings = []
    for c in _get_containers(resource):
        resources = c.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(_finding(
                "K8S-006", "MEDIUM", context,
                f"Missing resource limits: {c.get('name')}",
                "CPU and/or memory limits are not set. This enables resource exhaustion (DoS) attacks.",
                "Set resources.limits.cpu and resources.limits.memory for every container.",
                f"spec.containers[{c.get('name')}].resources.limits"
            ))
        if not requests.get("cpu") or not requests.get("memory"):
            findings.append(_finding(
                "K8S-006", "LOW", context,
                f"Missing resource requests: {c.get('name')}",
                "Resource requests not set — Kubernetes scheduler cannot make informed placement decisions.",
                "Set resources.requests.cpu and resources.requests.memory.",
                f"spec.containers[{c.get('name')}].resources.requests"
            ))
    return findings


def check_image_tag(resource, context):
    findings = []
    for c in _get_containers(resource):
        image = c.get("image", "")
        if image.endswith(":latest") or (":" not in image):
            findings.append(_finding(
                "K8S-007", "MEDIUM", context,
                f"Unpinned image tag: {c.get('name')}",
                f"Image '{image}' uses :latest or no tag. This causes unpredictable deployments and supply chain risk.",
                "Pin images to a specific digest (e.g., image@sha256:...) or an immutable semver tag.",
                f"spec.containers[{c.get('name')}].image"
            ))
    return findings


def check_service_account(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    if template_spec.get("automountServiceAccountToken") is not False:
        findings.append(_finding(
            "K8S-008", "MEDIUM", context,
            "Service account token auto-mounted",
            "automountServiceAccountToken is not explicitly set to false. "
            "Every pod gets an API token mounted at /var/run/secrets — useful for lateral movement.",
            "Set automountServiceAccountToken: false unless the pod genuinely needs API access.",
            "spec.automountServiceAccountToken"
        ))
    return findings


def check_host_path_volumes(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    for vol in template_spec.get("volumes", []):
        if "hostPath" in vol:
            path = vol["hostPath"].get("path", "")
            sev = "CRITICAL" if path in ("/", "/etc", "/proc", "/sys", "/var/run/docker.sock") else "HIGH"
            findings.append(_finding(
                "K8S-009", sev, context,
                f"hostPath volume mounted: {vol.get('name')}",
                f"Volume mounts host path '{path}'. This can expose sensitive host data or allow container escape.",
                "Avoid hostPath volumes. Use PersistentVolumeClaims or ConfigMaps instead.",
                f"spec.volumes[{vol.get('name')}].hostPath"
            ))
    return findings


def check_network_policy(resource, context):
    # Only flag for Deployments/DaemonSets/StatefulSets — not for NetworkPolicy itself
    if resource.get("kind") in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
        labels = resource.get("metadata", {}).get("labels", {})
        if not labels:
            return _finding(
                "K8S-010", "LOW", context,
                "No labels defined — NetworkPolicy targeting may be impaired",
                "Resources without labels cannot be targeted by NetworkPolicy selectors, "
                "leaving pod-level network isolation undefined.",
                "Add meaningful labels (app, tier, environment) to enable NetworkPolicy targeting.",
                "metadata.labels"
            )
    return None


def check_secrets_in_env(resource, context):
    findings = []
    sensitive_keys = {"password", "secret", "token", "key", "api_key", "apikey", "passwd", "credential"}
    for c in _get_containers(resource):
        for env in c.get("env", []):
            name_lower = env.get("name", "").lower()
            if any(k in name_lower for k in sensitive_keys):
                if "value" in env:  # hardcoded — not using valueFrom
                    findings.append(_finding(
                        "K8S-011", "HIGH", context,
                        f"Hardcoded secret in env var: {env.get('name')}",
                        f"Environment variable '{env.get('name')}' appears to contain a secret hardcoded as plaintext.",
                        "Use secretKeyRef to reference a Kubernetes Secret instead of hardcoding values.",
                        f"spec.containers[{c.get('name')}].env[{env.get('name')}]"
                    ))
    return findings


def check_liveness_readiness(resource, context):
    findings = []
    for c in _get_containers(resource):
        if not c.get("livenessProbe"):
            findings.append(_finding(
                "K8S-012", "LOW", context,
                f"No liveness probe: {c.get('name')}",
                "Without a liveness probe, Kubernetes cannot detect and recover from application deadlocks.",
                "Add a livenessProbe (httpGet, exec, or tcpSocket) to enable automatic pod restart on failure.",
                f"spec.containers[{c.get('name')}].livenessProbe"
            ))
        if not c.get("readinessProbe"):
            findings.append(_finding(
                "K8S-012", "LOW", context,
                f"No readiness probe: {c.get('name')}",
                "Without a readiness probe, a failing container may still receive traffic.",
                "Add a readinessProbe to gate traffic until the container is actually ready.",
                f"spec.containers[{c.get('name')}].readinessProbe"
            ))
    return findings


def check_security_context(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    pod_sc = template_spec.get("securityContext", {})
    if not pod_sc:
        findings.append(_finding(
            "K8S-013", "MEDIUM", context,
            "No pod-level securityContext defined",
            "Pod-level securityContext is missing. Best practice is to set runAsNonRoot, "
            "runAsUser, fsGroup, and seccompProfile at the pod level.",
            "Add a securityContext block to the pod spec with at minimum runAsNonRoot: true and a seccompProfile.",
            "spec.securityContext"
        ))
    if pod_sc and not pod_sc.get("seccompProfile"):
        findings.append(_finding(
            "K8S-013", "LOW", context,
            "No seccomp profile defined",
            "seccompProfile is not set. Without it, containers can make any syscall the kernel allows.",
            "Set securityContext.seccompProfile.type: RuntimeDefault or a custom profile.",
            "spec.securityContext.seccompProfile"
        ))
    return findings


def check_rbac_wildcard(resource, context):
    findings = []
    if resource.get("kind") in ("ClusterRole", "Role"):
        for rule in resource.get("rules", []):
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            api_groups = rule.get("apiGroups", [])
            if "*" in verbs:
                findings.append(_finding(
                    "K8S-014", "HIGH", context,
                    "Wildcard verb in RBAC rule",
                    f"Rule grants wildcard (*) verbs on resources: {resources}. This is overly permissive.",
                    "Replace wildcard verbs with the minimum required verbs (get, list, watch).",
                    "rules[].verbs"
                ))
            if "*" in resources:
                findings.append(_finding(
                    "K8S-014", "CRITICAL", context,
                    "Wildcard resource in RBAC rule",
                    "Rule grants access to all (*) resources. This effectively grants cluster-admin-like access.",
                    "Enumerate the specific resources the role needs access to.",
                    "rules[].resources"
                ))
    return findings
