# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
claude_agent.py — Agentic analysis loop using Anthropic tool_use API

Claude drives the analysis: it decides which checks to run, which images
to scan for CVEs, and what additional findings to report — rather than
following a fixed pipeline.
"""

import json
import os
import anthropic
from pathlib import Path
from typing import Dict, List, Tuple

from tools import TOOLS, execute_tool

DEFAULT_MODEL = os.environ.get("K8S_CHECKER_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are a senior Kubernetes security architect with deep expertise in:
- NSA/CISA Kubernetes Hardening Guide
- CIS Kubernetes Benchmark
- MITRE ATT&CK for Containers
- Telco/CNF security (5G core, CNF sidecars, service mesh)
- Supply chain security (image provenance, SBOMs, CVEs)

You have access to the following tools. Use them methodically:

**Loading manifests:**
- If the input is a regular YAML file or directory: call load_manifest (handles both automatically)
- If the input is a Helm chart directory (contains Chart.yaml): call render_helm_chart first

**Static analysis:**
- Run run_check with check_id='ALL' and resource_index=-1 for a full sweep of all loaded resources

**CVE scanning:**
- For every unique container image found, call lookup_image_cves

**Live cluster analysis (if kubectl is available):**
- Call query_cluster to inspect the running state: pods, RBAC bindings, NetworkPolicies, Secrets
- Compare declared (manifest) vs runtime state for drift
- Check namespace-wide RBAC: clusterrolebindings, rolebindings
- Look for pods with no NetworkPolicy coverage across namespaces

**AI findings:**
- Use report_finding for issues the static checks did not catch:
  - Logic-level misconfigurations (insecure inter-service trust, permissive ingress)
  - Supply chain risks beyond static rules
  - Missing AppArmor / seccomp annotations
  - Telco/CNF concerns (5G NF sidecars, service mesh misconfig, DPDK, CNI)
  - Compound-risk chains where multiple findings amplify each other
  - Runtime vs declared state mismatches

**Finishing:**
- Call finish() when analysis is complete

Be thorough but avoid re-running checks you have already completed."""


MAX_ITERATIONS = 25


def analyze_with_agent(
    manifest_path: Path,
    api_key: str,
    verbose: bool = True,
    model: str = None,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Run the agentic analysis loop.
    Returns (resources, findings).
    """
    client = anthropic.Anthropic(api_key=api_key)
    model = model or DEFAULT_MODEL

    state: Dict = {
        "resources": [],
        "findings":  [],
        "done":      False,
        "summary":   "",
    }

    if manifest_path.is_dir() and (manifest_path / "Chart.yaml").exists():
        input_hint = (
            f"'{manifest_path}' is a Helm chart directory. "
            "Use render_helm_chart to render it before running checks."
        )
    elif manifest_path.is_dir():
        input_hint = (
            f"'{manifest_path}' is a directory. "
            "Call load_manifest with this directory path — it will automatically load all YAML files inside."
        )
    else:
        input_hint = f"'{manifest_path}' is a YAML file. Call load_manifest to parse it."

    messages = [
        {
            "role": "user",
            "content": (
                f"Analyze '{manifest_path}' for Kubernetes security misconfigurations. {input_hint} "
                "Be thorough: run all static checks, scan container images for CVEs, query the live "
                "cluster if kubectl is available, and report every finding. Call finish() when done."
            ),
        }
    ]

    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                if verbose:
                    _log_tool_call(block.name, block.input)

                result = execute_tool(block.name, block.input, state)

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     json.dumps(result),
                })

        messages.append({"role": "user", "content": tool_results})

        if state.get("done"):
            break

    return state["resources"], state["findings"]


_TOOL_ICONS = {
    "load_manifest":     "📂",
    "render_helm_chart": "⎈",
    "query_cluster":     "🌐",
    "run_check":         "🔍",
    "lookup_image_cves": "🛡",
    "report_finding":    "⚠",
    "finish":            "✅",
}


def _log_tool_call(name: str, input_data: Dict) -> None:
    icon = _TOOL_ICONS.get(name, "🔧")

    if name == "run_check":
        detail = f"check={input_data.get('check_id')}  resource={input_data.get('resource_index')}"
    elif name == "lookup_image_cves":
        detail = input_data.get("image", "")
    elif name == "report_finding":
        detail = f"[{input_data.get('severity')}] {input_data.get('title', '')}"
    elif name == "finish":
        detail = (input_data.get("summary") or "")[:80]
    else:
        detail = str(input_data)[:80]

    print(f"      {icon}  {name}({detail})")
