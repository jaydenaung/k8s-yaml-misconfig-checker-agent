# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
tools.py — Tool schemas and execution functions for the K8s security agent
"""

import json
import os
import subprocess
import yaml
from pathlib import Path
from typing import Any, Dict, List

from analyzer import load_manifests, run_check_by_id


TOOLS = [
    {
        "name": "load_manifest",
        "description": (
            "Parse Kubernetes YAML manifests and return the list of resources found. "
            "Accepts a single file path OR a directory path (loads all .yaml/.yml files recursively). "
            "Call this first before running any checks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to a Kubernetes YAML file or a directory containing YAML files"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "render_helm_chart",
        "description": (
            "Render a Helm chart to Kubernetes YAML using 'helm template', then load the resources for analysis. "
            "Use this when the input path contains a Chart.yaml file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "chart_path": {
                    "type": "string",
                    "description": "Path to the Helm chart directory (must contain Chart.yaml)"
                },
                "release_name": {
                    "type": "string",
                    "description": "Release name for helm template (default: release)"
                },
                "values_file": {
                    "type": "string",
                    "description": "Optional path to a values override file (e.g. values-prod.yaml)"
                }
            },
            "required": ["chart_path"]
        }
    },
    {
        "name": "query_cluster",
        "description": (
            "Query a live Kubernetes cluster using kubectl. Returns compact security fingerprints — "
            "not raw JSON — so results are token-efficient. Each pod/workload includes a 'signals' list "
            "of pre-computed security flags (e.g. 'privileged:api', 'root_user:init', 'hostPID', "
            "'sa_token_automounted'). RBAC roles include 'sensitive' access list and wildcard flags. "
            "NetworkPolicies include 'namespaces_covered'. Use this to check runtime state: running pods, "
            "RBAC bindings, NetworkPolicies, Secrets (names only). Requires kubectl to be configured."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "description": (
                        "Kubernetes resource type to query. Examples: "
                        "pods, deployments, services, secrets, configmaps, "
                        "networkpolicies, serviceaccounts, "
                        "roles, rolebindings, clusterroles, clusterrolebindings, namespaces"
                    )
                },
                "name": {
                    "type": "string",
                    "description": "Specific resource name. Omit to list all."
                },
                "namespace": {
                    "type": "string",
                    "description": "Namespace to query. Use 'all' for all namespaces. Omit for default."
                }
            },
            "required": ["resource_type"]
        }
    },
    {
        "name": "run_check",
        "description": (
            "Run a static security check on one or all loaded resources. "
            "Findings are automatically recorded. "
            "Use check_id='ALL' to run every check. "
            "Use resource_index=-1 to check all resources."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "check_id": {
                    "type": "string",
                    "description": (
                        "K8S-001 privileged containers | K8S-002 host namespaces | "
                        "K8S-003 root user | K8S-004 capabilities | K8S-005 read-only fs | "
                        "K8S-006 resource limits | K8S-007 image tags | K8S-008 service account token | "
                        "K8S-009 hostPath volumes | K8S-010 network policy labels | "
                        "K8S-011 secrets in env | K8S-012 liveness/readiness probes | "
                        "K8S-013 security context | K8S-014 RBAC wildcards | ALL"
                    )
                },
                "resource_index": {
                    "type": "integer",
                    "description": "0-based index of the resource to check. Use -1 for all resources."
                }
            },
            "required": ["check_id", "resource_index"]
        }
    },
    {
        "name": "lookup_image_cves",
        "description": (
            "Scan a container image for known CVEs using Trivy. "
            "Returns counts by severity and top critical findings. "
            "Requires Trivy CLI to be installed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "image": {
                    "type": "string",
                    "description": "Container image reference, e.g. nginx:latest or redis:7.0.5-alpine"
                }
            },
            "required": ["image"]
        }
    },
    {
        "name": "report_finding",
        "description": (
            "Record a security finding you identified that the static checks did not catch. "
            "Use this for logic-level issues, supply chain risks, inter-service trust problems, "
            "cluster runtime misconfigurations, and telco/CNF-specific concerns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "check_id":        {"type": "string", "description": "AI-prefixed ID, e.g. AI-001"},
                "severity":        {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "context":         {"type": "string", "description": "Resource context, e.g. Deployment/my-app"},
                "title":           {"type": "string", "description": "Short title of the finding"},
                "detail":          {"type": "string", "description": "What the problem is and why it matters"},
                "remediation":     {"type": "string", "description": "Specific steps to fix it"},
                "resource_path":   {"type": "string", "description": "YAML path to the problematic field"},
                "attack_scenario": {"type": "string", "description": "One sentence: how an attacker exploits this"},
                "telco_relevance": {"type": "string", "description": "Relevance to telco/CNF workloads"}
            },
            "required": ["check_id", "severity", "context", "title", "detail", "remediation"]
        }
    },
    {
        "name": "probe_service_account",
        "description": (
            "Probe what a Kubernetes service account can actually access at runtime, "
            "using kubectl auth can-i impersonation. Call this after finding auto-mounted "
            "SA tokens (K8S-008) or suspicious RBAC bindings (K8S-014). "
            "Returns confirmed access (secrets, configmaps, pods, etc.) as structured data — "
            "proving exploitability, not just theoretical risk."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace where the service account lives"
                },
                "service_account": {
                    "type": "string",
                    "description": "Name of the service account to probe"
                },
                "target_namespace": {
                    "type": "string",
                    "description": "Namespace to check access in. Omit to check in the SA's own namespace."
                }
            },
            "required": ["namespace", "service_account"]
        }
    },
    {
        "name": "scan_cluster_images",
        "description": (
            "Scan container images running in the cluster for CVEs using Trivy. "
            "Gets images from running pods via kubectl (or from loaded manifest resources), "
            "deduplicates, scans each with Trivy, and returns CVE counts per image with the "
            "pods running them. Use after probe_service_account to build compound risk findings: "
            "correlate CVE signals with misconfiguration and RBAC signals on the same pod."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to query pods from. Use 'all' for all namespaces (default)."
                }
            },
            "required": []
        }
    },
    {
        "name": "suggest_patch",
        "description": (
            "Generate and record a corrected YAML patch for a specific finding. "
            "Call this immediately after every report_finding call, and after run_check "
            "identifies static findings. Use the same check_id and context as the finding. "
            "Provide the minimal corrected YAML snippet — just the fixed field(s) with "
            "enough parent-key context to be unambiguous."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "check_id": {
                    "type": "string",
                    "description": "The check ID this patch addresses — must match the finding (e.g. K8S-001 or AI-001)"
                },
                "context": {
                    "type": "string",
                    "description": "Resource context — must match the finding (e.g. Deployment/nginx)"
                },
                "patch_yaml": {
                    "type": "string",
                    "description": (
                        "Corrected YAML snippet showing the fixed field(s) with parent key context. "
                        "Example for a root-user finding:\n"
                        "spec:\n"
                        "  template:\n"
                        "    spec:\n"
                        "      securityContext:\n"
                        "        runAsNonRoot: true\n"
                        "        runAsUser: 1000"
                    )
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explaining what was changed and why it fixes the issue."
                }
            },
            "required": ["check_id", "context", "patch_yaml", "explanation"]
        }
    },
    {
        "name": "finish",
        "description": "End the analysis. Call this when all checks are complete and all findings are reported.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Brief summary of the analysis performed and key findings"
                }
            },
            "required": ["summary"]
        }
    }
]


def execute_tool(name: str, input_data: Dict, state: Dict) -> Any:
    dispatch = {
        "load_manifest":          _load_manifest,
        "render_helm_chart":      _render_helm_chart,
        "query_cluster":          _query_cluster,
        "run_check":              _run_check,
        "lookup_image_cves":      _lookup_image_cves,
        "report_finding":         _report_finding,
        "probe_service_account":  _probe_service_account,
        "scan_cluster_images":    _scan_cluster_images,
        "suggest_patch":          _suggest_patch,
        "finish":                 _finish,
    }
    fn = dispatch.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    return fn(input_data, state)


# ── Tool implementations ──────────────────────────────────────────────────────

def _load_manifest(input_data: Dict, state: Dict) -> Dict:
    path = Path(input_data["path"])
    if not path.exists():
        return {"error": f"Path not found: {path}"}

    resources = load_manifests(path)
    state["resources"] = resources

    summary = [
        {
            "index": i,
            "kind": r.get("kind", "Unknown"),
            "name": r.get("metadata", {}).get("name", "unnamed"),
            "namespace": r.get("metadata", {}).get("namespace", "default"),
            "source_file": r.get("_source_file", str(path)),
        }
        for i, r in enumerate(resources)
    ]
    files_loaded = len({r.get("_source_file") for r in resources})
    return {"files_loaded": files_loaded, "resources": summary, "count": len(resources)}


def _render_helm_chart(input_data: Dict, state: Dict) -> Dict:
    chart_path = input_data["chart_path"]
    release_name = input_data.get("release_name", "release")
    values_file = input_data.get("values_file")

    cmd = ["helm", "template", release_name, chart_path]
    if values_file:
        cmd.extend(["-f", values_file])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"error": result.stderr[:500] or "helm template failed"}

        resources = []
        for doc in yaml.safe_load_all(result.stdout):
            if doc is not None:
                doc["_source_file"] = f"helm:{chart_path}"
                resources.append(doc)

        state["resources"] = resources
        summary = [
            {
                "index": i,
                "kind": r.get("kind", "Unknown"),
                "name": r.get("metadata", {}).get("name", "unnamed"),
                "namespace": r.get("metadata", {}).get("namespace", "default"),
            }
            for i, r in enumerate(resources)
        ]
        return {"chart": chart_path, "release": release_name, "resources": summary, "count": len(resources)}

    except FileNotFoundError:
        return {"available": False, "message": "helm not installed or not in PATH"}
    except subprocess.TimeoutExpired:
        return {"error": "helm template timed out after 60s"}
    except Exception as e:
        return {"error": str(e)}


_ALLOWED_RESOURCE_TYPES = {
    "pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
    "services", "endpoints", "ingresses",
    "configmaps", "secrets", "serviceaccounts",
    "networkpolicies",
    "roles", "rolebindings", "clusterroles", "clusterrolebindings",
    "namespaces", "nodes", "persistentvolumes", "persistentvolumeclaims",
    "resourcequotas", "limitranges", "podsecuritypolicies", "poddisruptionbudgets",
}


def _query_cluster(input_data: Dict, state: Dict) -> Dict:
    resource_type = input_data["resource_type"].lower().strip()
    name = input_data.get("name", "")
    namespace = input_data.get("namespace", "")

    if resource_type not in _ALLOWED_RESOURCE_TYPES:
        return {
            "error": (
                f"Resource type '{resource_type}' is not in the allowed list. "
                f"Allowed types: {sorted(_ALLOWED_RESOURCE_TYPES)}"
            )
        }

    cmd = ["kubectl", "get", resource_type]
    if name:
        cmd.append(name)
    if namespace == "all":
        cmd.append("-A")
    elif namespace:
        cmd.extend(["-n", namespace])
    cmd.extend(["-o", "json"])

    env = dict(os.environ)
    if state.get("kubeconfig_path"):
        env["KUBECONFIG"] = state["kubeconfig_path"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        if result.returncode != 0:
            return {"error": result.stderr[:500] or "kubectl returned non-zero exit code"}

        data = json.loads(result.stdout)
        return _fingerprint_cluster_resource(data)

    except FileNotFoundError:
        return {"available": False, "message": "kubectl not installed or not configured"}
    except subprocess.TimeoutExpired:
        return {"error": "kubectl timed out after 30s"}
    except json.JSONDecodeError:
        return {"error": "Could not parse kubectl JSON output"}
    except Exception as e:
        return {"error": str(e)}


# ── Security fingerprinting layer ─────────────────────────────────────────────
# Converts raw kubectl JSON into compact, security-focused fingerprints.
# Target: <10 KB per query_cluster call regardless of cluster size.
# (vs. 500 KB+ for raw kubectl JSON on real clusters)

_SENSITIVE_RESOURCES = {
    "secrets", "configmaps", "pods", "deployments", "nodes",
    "serviceaccounts", "clusterrolebindings", "rolebindings", "namespaces",
    "persistentvolumes",
}

_WORKLOAD_LIST_KINDS = {
    "DeploymentList", "DaemonSetList", "StatefulSetList",
    "ReplicaSetList", "JobList", "CronJobList",
}


def _fp_container(c: Dict) -> Dict:
    sc   = c.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    return {
        "name":        c.get("name", ""),
        "image":       c.get("image", ""),
        "privileged":  sc.get("privileged", False),
        "runAsUser":   sc.get("runAsUser"),
        "runAsNonRoot": sc.get("runAsNonRoot"),
        "readOnlyFS":  sc.get("readOnlyRootFilesystem", False),
        "allowPrivEsc": sc.get("allowPrivilegeEscalation"),
        "caps_add":    caps.get("add", []),
        "caps_drop":   caps.get("drop", []),
    }


def _pod_signals(spec: Dict, containers: List[Dict]) -> List[str]:
    """Pre-compute security signals so Claude can triage without re-parsing."""
    sigs: List[str] = []
    if spec.get("hostPID"):
        sigs.append("hostPID")
    if spec.get("hostIPC"):
        sigs.append("hostIPC")
    if spec.get("hostNetwork"):
        sigs.append("hostNetwork")
    if spec.get("automountServiceAccountToken") is not False:
        sigs.append("sa_token_automounted")
    for c in containers:
        n = c["name"]
        if c.get("privileged"):
            sigs.append(f"privileged:{n}")
        ru = c.get("runAsUser")
        if ru == 0 or (ru is None and not c.get("runAsNonRoot")):
            sigs.append(f"root_user:{n}")
        if not c.get("readOnlyFS"):
            sigs.append(f"writable_fs:{n}")
        if c.get("allowPrivEsc") is not False:
            sigs.append(f"priv_esc_allowed:{n}")
        if c.get("caps_add"):
            sigs.append(f"caps_add[{','.join(c['caps_add'])}]:{n}")
    host_paths = [
        v.get("hostPath", {}).get("path")
        for v in spec.get("volumes", [])
        if "hostPath" in v and v.get("hostPath", {}).get("path")
    ]
    if host_paths:
        sigs.append(f"hostPath:{','.join(host_paths)}")
    return sigs


def _fp_pod(pod: Dict) -> Dict:
    meta           = pod.get("metadata", {})
    spec           = pod.get("spec", {})
    containers     = [_fp_container(c) for c in spec.get("containers", [])]
    init_containers = [_fp_container(c) for c in spec.get("initContainers", [])]
    return {
        "name":         meta.get("name", ""),
        "ns":           meta.get("namespace", "default"),
        "phase":        pod.get("status", {}).get("phase"),
        "sa":           spec.get("serviceAccountName", "default"),
        "hostPID":      spec.get("hostPID", False),
        "hostIPC":      spec.get("hostIPC", False),
        "hostNet":      spec.get("hostNetwork", False),
        "containers":   containers,
        "initContainers": init_containers or None,
        "signals":      _pod_signals(spec, containers + init_containers),
    }


def _fp_workload(r: Dict) -> Dict:
    meta     = r.get("metadata", {})
    spec     = r.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    containers = [_fp_container(c) for c in pod_spec.get("containers", [])]
    return {
        "name":     meta.get("name", ""),
        "ns":       meta.get("namespace", "default"),
        "replicas": spec.get("replicas", 1),
        "sa":       pod_spec.get("serviceAccountName", "default"),
        "containers": containers,
        "signals":  _pod_signals(pod_spec, containers),
    }


def _fp_rbac_role(r: Dict) -> Dict:
    meta  = r.get("metadata", {})
    rules = r.get("rules") or []
    wildcard_verb = any("*" in (rule.get("verbs") or []) for rule in rules)
    wildcard_res  = any("*" in (rule.get("resources") or []) for rule in rules)
    sensitive: List[str] = []
    for rule in rules:
        for v in (rule.get("verbs") or []):
            for res in (rule.get("resources") or []):
                if v == "*" or res == "*" or res in _SENSITIVE_RESOURCES:
                    entry = f"{v} {res}"
                    if entry not in sensitive:
                        sensitive.append(entry)
    return {
        "name":          meta.get("name", ""),
        "ns":            meta.get("namespace"),
        "wildcard_verb": wildcard_verb,
        "wildcard_res":  wildcard_res,
        "sensitive":     sensitive[:12],
        "rule_count":    len(rules),
    }


def _fp_rbac_binding(b: Dict) -> Dict:
    meta     = b.get("metadata", {})
    role_ref = b.get("roleRef", {})
    subjects = [
        {"kind": s.get("kind"), "name": s.get("name"), "ns": s.get("namespace")}
        for s in (b.get("subjects") or [])
    ]
    return {
        "name":         meta.get("name", ""),
        "ns":           meta.get("namespace"),
        "role":         role_ref.get("name", ""),
        "subjects":     subjects,
        "cluster_admin": role_ref.get("name") in ("cluster-admin", "admin"),
    }


def _fp_network_policy(np: Dict) -> Dict:
    meta = np.get("metadata", {})
    spec = np.get("spec", {})
    return {
        "name":        meta.get("name", ""),
        "ns":          meta.get("namespace", ""),
        "selector":    spec.get("podSelector", {}).get("matchLabels"),
        "policyTypes": spec.get("policyTypes", []),
        "ingress":     len(spec.get("ingress") or []),
        "egress":      len(spec.get("egress") or []),
    }


def _fingerprint_cluster_resource(data: Dict) -> Dict:
    """Convert raw kubectl JSON into compact security fingerprints.

    Output sizes (approximate):
      PodList (50 pods):            ~6 KB   (was up to 300 KB)
      ClusterRoleList (100 roles):  ~5 KB   (was up to 200 KB)
      SecretList (30 secrets):      ~1 KB   (was 500 KB+ with base64 data)
    """
    kind  = data.get("kind", "")
    items = data.get("items", [])

    # kubectl returns kind="List" when querying with -A; detect real type from first item.
    if kind == "List" and items:
        item_kind = items[0].get("kind", "")
        kind = (item_kind + "List") if item_kind else kind

    if kind == "PodList":
        fps = [_fp_pod(p) for p in items[:50]]
        return {"kind": "PodList", "total": len(items),
                "flagged": sum(1 for f in fps if f["signals"]), "items": fps}

    if kind in _WORKLOAD_LIST_KINDS:
        fps = [_fp_workload(r) for r in items[:30]]
        return {"kind": kind, "total": len(items),
                "flagged": sum(1 for f in fps if f["signals"]), "items": fps}

    if kind in ("ClusterRoleList", "RoleList"):
        fps = [_fp_rbac_role(r) for r in items[:60]]
        return {"kind": kind, "total": len(items),
                "flagged": sum(1 for f in fps if f["wildcard_verb"] or f["wildcard_res"] or f["sensitive"]),
                "items": fps}

    if kind in ("ClusterRoleBindingList", "RoleBindingList"):
        fps = [_fp_rbac_binding(b) for b in items[:60]]
        return {"kind": kind, "total": len(items),
                "flagged": sum(1 for f in fps if f["cluster_admin"]), "items": fps}

    if kind == "NetworkPolicyList":
        fps = [_fp_network_policy(np) for np in items]
        return {"kind": "NetworkPolicyList", "total": len(items),
                "namespaces_covered": sorted({f["ns"] for f in fps}), "items": fps}

    if kind == "SecretList":
        fps = [
            {"name": s["metadata"]["name"], "ns": s["metadata"].get("namespace"), "type": s.get("type")}
            for s in items[:50]
        ]
        return {"kind": "SecretList", "total": len(items), "items": fps}

    if kind == "ServiceAccountList":
        fps = [
            {"name": s["metadata"]["name"], "ns": s["metadata"].get("namespace"),
             "automount": s.get("automountServiceAccountToken")}
            for s in items[:50]
        ]
        return {"kind": "ServiceAccountList", "total": len(items), "items": fps}

    if kind == "NamespaceList":
        fps = [
            {"name": ns["metadata"]["name"], "labels": ns["metadata"].get("labels", {}),
             "phase": ns.get("status", {}).get("phase")}
            for ns in items
        ]
        return {"kind": "NamespaceList", "total": len(items), "items": fps}

    # Generic fallback — names only, no raw data
    if items:
        return {
            "kind":  kind,
            "total": len(items),
            "items": [
                {"name": i.get("metadata", {}).get("name"), "ns": i.get("metadata", {}).get("namespace")}
                for i in items[:20]
            ],
        }

    # Single resource (not a list)
    meta = data.get("metadata", {})
    return {"kind": kind, "name": meta.get("name"), "ns": meta.get("namespace")}


def _run_check(input_data: Dict, state: Dict) -> Dict:
    if not state.get("resources"):
        return {"error": "No manifest loaded. Call load_manifest or render_helm_chart first."}

    check_id = input_data["check_id"]
    resource_index = input_data["resource_index"]
    resources = state["resources"]

    if resource_index == -1:
        targets = list(range(len(resources)))
    elif 0 <= resource_index < len(resources):
        targets = [resource_index]
    else:
        return {"error": f"resource_index {resource_index} out of range (0–{len(resources) - 1})"}

    new_findings = []
    for idx in targets:
        results = run_check_by_id(check_id, resources[idx])
        for f in results:
            f["source"] = "static"
            key = (f["check_id"], f.get("context"), f.get("title"))
            if not any(
                (x["check_id"], x.get("context"), x.get("title")) == key
                for x in state["findings"]
            ):
                state["findings"].append(f)
                new_findings.append(f)

    return {
        "check_id": check_id,
        "resources_checked": len(targets),
        "new_findings": len(new_findings),
        "findings": new_findings,
    }


def _trivy_image_scan(image: str) -> Dict:
    """Shared Trivy helper — returns CVE counts + top critical CVEs, or {} on any failure."""
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", "--no-progress", image],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return {}
        data = json.loads(result.stdout)
        counts: Dict[str, int] = {}
        top_critical: list = []
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                sev = v.get("Severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
                if sev == "CRITICAL" and len(top_critical) < 5:
                    top_critical.append({
                        "id":      v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "fixed":   v.get("FixedVersion"),
                    })
        return {
            "critical":     counts.get("CRITICAL", 0),
            "high":         counts.get("HIGH", 0),
            "medium":       counts.get("MEDIUM", 0),
            "low":          counts.get("LOW", 0),
            "total":        sum(counts.values()),
            "top_critical": top_critical,
        }
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def _lookup_image_cves(input_data: Dict, state: Dict) -> Dict:
    image = input_data["image"]
    cves = _trivy_image_scan(image)
    if not cves:
        return {"available": False, "message": "Trivy not installed or scan failed. Install from https://aquasecurity.github.io/trivy/"}
    return {
        "image":                    image,
        "vulnerability_counts":     {k: cves[k] for k in ("critical", "high", "medium", "low")},
        "critical_vulnerabilities": cves.get("top_critical", []),
        "total":                    cves["total"],
    }


def _report_finding(input_data: Dict, state: Dict) -> Dict:
    finding = {
        "source":          "claude-ai",
        "check_id":        input_data.get("check_id", "AI-000"),
        "severity":        input_data.get("severity", "INFO"),
        "context":         input_data.get("context", ""),
        "title":           input_data.get("title", ""),
        "detail":          input_data.get("detail", ""),
        "remediation":     input_data.get("remediation", ""),
        "resource_path":   input_data.get("resource_path", ""),
        "attack_scenario": input_data.get("attack_scenario", ""),
        "telco_relevance": input_data.get("telco_relevance", ""),
    }
    state["findings"].append(finding)
    return {"recorded": True, "check_id": finding["check_id"], "severity": finding["severity"]}


_SA_SENSITIVE_CHECKS = [
    ("get",    "secrets"),
    ("list",   "secrets"),
    ("get",    "configmaps"),
    ("list",   "configmaps"),
    ("create", "pods"),
    ("delete", "pods"),
    ("create", "deployments"),
    ("delete", "deployments"),
    ("list",   "serviceaccounts"),
    ("create", "clusterrolebindings"),
    ("delete", "clusterrolebindings"),
    ("list",   "namespaces"),
    ("get",    "nodes"),
]


def _probe_service_account(input_data: Dict, state: Dict) -> Dict:
    namespace      = input_data.get("namespace", "default")
    sa_name        = input_data.get("service_account", "default")
    target_ns      = input_data.get("target_namespace") or namespace

    env = dict(os.environ)
    if state.get("kubeconfig_path"):
        env["KUBECONFIG"] = state["kubeconfig_path"]

    as_flag = f"system:serviceaccount:{namespace}:{sa_name}"

    confirmed, denied, errors = [], [], []
    for verb, resource in _SA_SENSITIVE_CHECKS:
        cmd = ["kubectl", "auth", "can-i", verb, resource, f"--as={as_flag}", "-n", target_ns]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
            (confirmed if r.returncode == 0 and r.stdout.strip() == "yes" else denied).append(
                f"{verb} {resource}"
            )
        except FileNotFoundError:
            return {"available": False, "message": "kubectl not installed or not configured"}
        except Exception as e:
            errors.append(f"{verb} {resource}: {str(e)[:60]}")

    # Find pods in state that mount this SA
    pods_using_sa = []
    for r in state.get("resources", []):
        spec = r.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        if pod_spec.get("serviceAccountName", "default") == sa_name:
            kind = r.get("kind", "Pod")
            name = r.get("metadata", {}).get("name", "unknown")
            pods_using_sa.append(f"{kind}/{name}")

    has_secret_access = any("secrets" in c for c in confirmed)
    risk_level = (
        "CRITICAL" if (has_secret_access or "create clusterrolebindings" in confirmed)
        else "HIGH" if confirmed
        else "LOW"
    )

    return {
        "service_account":  sa_name,
        "namespace":        namespace,
        "target_namespace": target_ns,
        "pods_using_sa":    pods_using_sa,
        "confirmed_access": confirmed,
        "denied":           denied,
        "risk_level":       risk_level,
        "errors":           errors,
        "summary": (
            f"SA '{sa_name}' can: {', '.join(confirmed)}." if confirmed
            else f"SA '{sa_name}' has no dangerous confirmed access."
        ),
    }


def _scan_cluster_images(input_data: Dict, state: Dict) -> Dict:
    namespace = input_data.get("namespace", "all")
    env = dict(os.environ)
    if state.get("kubeconfig_path"):
        env["KUBECONFIG"] = state["kubeconfig_path"]

    # Build image → [pod contexts] from state resources (manifest scan)
    # or from live cluster (cluster scan)
    image_pods: Dict[str, list] = {}

    if state.get("resources"):
        for r in state["resources"]:
            spec = r.get("spec", {})
            pod_spec = spec.get("template", {}).get("spec", spec)
            kind = r.get("kind", "Pod")
            name = r.get("metadata", {}).get("name", "unknown")
            ctx  = f"{kind}/{name}"
            for c in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
                img = c.get("image")
                if img:
                    image_pods.setdefault(img, []).append(ctx)
    else:
        cmd = ["kubectl", "get", "pods", "-o", "json"]
        cmd += ["-A"] if namespace == "all" else ["-n", namespace]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
            if r.returncode != 0:
                return {"error": r.stderr[:300] or "kubectl failed"}
            for pod in json.loads(r.stdout).get("items", []):
                ns   = pod["metadata"].get("namespace", "default")
                name = pod["metadata"]["name"]
                ctx  = f"Pod/{name} ({ns})"
                spec = pod.get("spec", {})
                for c in spec.get("containers", []) + spec.get("initContainers", []):
                    img = c.get("image")
                    if img:
                        image_pods.setdefault(img, []).append(ctx)
        except FileNotFoundError:
            return {"available": False, "message": "kubectl not installed or not configured"}
        except Exception as e:
            return {"error": str(e)}

    if not image_pods:
        return {"images_scanned": 0, "message": "No images found"}

    results = []
    for image, pods in image_pods.items():
        cves = _trivy_image_scan(image)
        results.append({
            "image":         image,
            "pods":          pods,
            "critical_cves": cves.get("critical", 0),
            "high_cves":     cves.get("high", 0),
            "medium_cves":   cves.get("medium", 0),
            "low_cves":      cves.get("low", 0),
            "total_cves":    cves.get("total", 0),
            "top_critical":  cves.get("top_critical", []),
            "trivy_available": bool(cves),
        })

    results.sort(key=lambda x: x["critical_cves"], reverse=True)
    high_risk = [r for r in results if r["critical_cves"] > 0 or r["high_cves"] > 5]

    return {
        "images_scanned":    len(results),
        "high_risk_images":  len(high_risk),
        "results":           results,
        "summary": (
            f"Scanned {len(results)} unique images. "
            f"{len(high_risk)} have significant CVEs (critical > 0 or high > 5)."
        ),
    }


def _suggest_patch(input_data: Dict, state: Dict) -> Dict:
    check_id  = input_data.get("check_id", "")
    context   = input_data.get("context", "")
    patch     = input_data.get("patch_yaml", "")
    explanation = input_data.get("explanation", "")

    # Attach patch to the most-recently-added matching finding (exact match first)
    for f in reversed(state["findings"]):
        if f.get("check_id") == check_id and f.get("context") == context:
            f["suggested_patch"]   = patch
            f["patch_explanation"] = explanation
            return {"recorded": True, "matched": "exact", "check_id": check_id}

    # Fallback: match by check_id only (for static findings where context may vary)
    for f in reversed(state["findings"]):
        if f.get("check_id") == check_id and not f.get("suggested_patch"):
            f["suggested_patch"]   = patch
            f["patch_explanation"] = explanation
            return {"recorded": True, "matched": "check_id_only", "check_id": check_id}

    return {"recorded": False, "reason": "no matching finding found", "check_id": check_id}


def _finish(input_data: Dict, state: Dict) -> Dict:
    state["done"] = True
    state["summary"] = input_data.get("summary", "")
    return {"status": "done", "total_findings": len(state["findings"])}
