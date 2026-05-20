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
from typing import Any, Dict

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
            "Query a live Kubernetes cluster using kubectl. "
            "Use this to check runtime state: running pods, RBAC bindings, NetworkPolicies, Secrets (names only). "
            "Requires kubectl to be configured and connected to a cluster."
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
        "load_manifest":     _load_manifest,
        "render_helm_chart": _render_helm_chart,
        "query_cluster":     _query_cluster,
        "run_check":         _run_check,
        "lookup_image_cves": _lookup_image_cves,
        "report_finding":    _report_finding,
        "finish":            _finish,
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
        return _summarize_cluster_resource(data)

    except FileNotFoundError:
        return {"available": False, "message": "kubectl not installed or not configured"}
    except subprocess.TimeoutExpired:
        return {"error": "kubectl timed out after 30s"}
    except json.JSONDecodeError:
        return {"error": "Could not parse kubectl JSON output"}
    except Exception as e:
        return {"error": str(e)}


def _summarize_cluster_resource(data: Dict) -> Dict:
    """Extract security-relevant fields only to avoid flooding Claude's context window."""
    kind = data.get("kind", "")

    if kind == "PodList":
        items = []
        for pod in data.get("items", [])[:20]:
            spec = pod.get("spec", {})
            items.append({
                "name":           pod["metadata"]["name"],
                "namespace":      pod["metadata"].get("namespace"),
                "phase":          pod.get("status", {}).get("phase"),
                "serviceAccount": spec.get("serviceAccountName"),
                "hostPID":        spec.get("hostPID"),
                "hostIPC":        spec.get("hostIPC"),
                "hostNetwork":    spec.get("hostNetwork"),
                "containers": [
                    {
                        "name":            c["name"],
                        "image":           c.get("image"),
                        "securityContext": c.get("securityContext"),
                    }
                    for c in spec.get("containers", [])
                ],
                "volumes": [
                    {"name": v["name"], "type": next((k for k in v if k != "name"), "unknown")}
                    for v in spec.get("volumes", [])
                ],
            })
        return {"kind": "PodList", "total": len(data.get("items", [])), "items": items}

    if kind in ("ClusterRoleBindingList", "RoleBindingList"):
        items = [
            {
                "name":      b["metadata"]["name"],
                "namespace": b["metadata"].get("namespace"),
                "roleRef":   b.get("roleRef"),
                "subjects":  b.get("subjects", []),
            }
            for b in data.get("items", [])[:30]
        ]
        return {"kind": kind, "total": len(data.get("items", [])), "items": items}

    if kind in ("ClusterRoleList", "RoleList"):
        items = [
            {
                "name":      r["metadata"]["name"],
                "namespace": r["metadata"].get("namespace"),
                "rules":     r.get("rules", []),
            }
            for r in data.get("items", [])[:30]
        ]
        return {"kind": kind, "total": len(data.get("items", [])), "items": items}

    if kind == "NetworkPolicyList":
        items = [
            {
                "name":        np["metadata"]["name"],
                "namespace":   np["metadata"].get("namespace"),
                "podSelector": np.get("spec", {}).get("podSelector"),
                "policyTypes": np.get("spec", {}).get("policyTypes"),
                "ingress":     np.get("spec", {}).get("ingress"),
                "egress":      np.get("spec", {}).get("egress"),
            }
            for np in data.get("items", [])
        ]
        return {"kind": "NetworkPolicyList", "total": len(items), "items": items}

    if kind == "SecretList":
        # Return names and types only — never expose secret values
        items = [
            {
                "name":      s["metadata"]["name"],
                "namespace": s["metadata"].get("namespace"),
                "type":      s.get("type"),
                "keys":      list((s.get("data") or {}).keys()),
            }
            for s in data.get("items", [])[:30]
        ]
        return {"kind": "SecretList", "total": len(data.get("items", [])), "items": items}

    # Generic fallback
    if "items" in data:
        return {"kind": kind, "total": len(data["items"]), "items": data["items"][:10]}
    return data


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


def _lookup_image_cves(input_data: Dict, state: Dict) -> Dict:
    image = input_data["image"]
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", "--no-progress", image],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode not in (0, 1):
            return {"error": result.stderr[:500] or "trivy returned unexpected exit code"}

        data = json.loads(result.stdout)
        counts: Dict[str, int] = {}
        critical_vulns = []

        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                sev = v.get("Severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
                if sev == "CRITICAL":
                    critical_vulns.append({
                        "id":        v.get("VulnerabilityID"),
                        "package":   v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed_in":  v.get("FixedVersion"),
                        "title":     (v.get("Title") or "")[:120],
                    })

        return {
            "image": image,
            "vulnerability_counts": counts,
            "critical_vulnerabilities": critical_vulns[:10],
            "total": sum(counts.values()),
        }

    except FileNotFoundError:
        return {"available": False, "message": "Trivy not installed. Install from https://aquasecurity.github.io/trivy/"}
    except subprocess.TimeoutExpired:
        return {"error": "Trivy scan timed out after 120s"}
    except json.JSONDecodeError:
        return {"error": "Could not parse Trivy JSON output"}
    except Exception as e:
        return {"error": str(e)}


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


def _finish(input_data: Dict, state: Dict) -> Dict:
    state["done"] = True
    state["summary"] = input_data.get("summary", "")
    return {"status": "done", "total_findings": len(state["findings"])}
