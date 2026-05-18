# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
tools.py — Tool schemas and execution functions for the K8s security agent
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict

from analyzer import load_manifests, run_check_by_id


TOOLS = [
    {
        "name": "load_manifest",
        "description": (
            "Parse a Kubernetes YAML manifest file and return the list of resources found. "
            "Call this first before running any checks."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the Kubernetes YAML manifest file"
                }
            },
            "required": ["path"]
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
            "and telco/CNF-specific concerns."
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
        "run_check":         _run_check,
        "lookup_image_cves": _lookup_image_cves,
        "report_finding":    _report_finding,
        "finish":            _finish,
    }
    fn = dispatch.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    return fn(input_data, state)


def _load_manifest(input_data: Dict, state: Dict) -> Dict:
    path = Path(input_data["path"])
    if not path.exists():
        return {"error": f"File not found: {path}"}
    resources = load_manifests(path)
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
    return {"resources": summary, "count": len(resources)}


def _run_check(input_data: Dict, state: Dict) -> Dict:
    if not state.get("resources"):
        return {"error": "No manifest loaded. Call load_manifest first."}

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
            # Deduplicate by check_id + context + title
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
        # trivy exits 1 when vulnerabilities are found — that is a normal result
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
        return {
            "available": False,
            "message": "Trivy not installed. Install from https://aquasecurity.github.io/trivy/",
        }
    except subprocess.TimeoutExpired:
        return {"error": "Trivy scan timed out after 120s"}
    except json.JSONDecodeError:
        return {"error": "Could not parse Trivy JSON output"}
    except Exception as e:
        return {"error": str(e)}


def _report_finding(input_data: Dict, state: Dict) -> Dict:
    finding = {
        "source":         "claude-ai",
        "check_id":       input_data.get("check_id", "AI-000"),
        "severity":       input_data.get("severity", "INFO"),
        "context":        input_data.get("context", ""),
        "title":          input_data.get("title", ""),
        "detail":         input_data.get("detail", ""),
        "remediation":    input_data.get("remediation", ""),
        "resource_path":  input_data.get("resource_path", ""),
        "attack_scenario":input_data.get("attack_scenario", ""),
        "telco_relevance":input_data.get("telco_relevance", ""),
    }
    state["findings"].append(finding)
    return {"recorded": True, "check_id": finding["check_id"], "severity": finding["severity"]}


def _finish(input_data: Dict, state: Dict) -> Dict:
    state["done"] = True
    state["summary"] = input_data.get("summary", "")
    return {"status": "done", "total_findings": len(state["findings"])}
