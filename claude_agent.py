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
import anthropic
from pathlib import Path
from typing import Dict, List, Tuple

from tools import TOOLS, execute_tool


SYSTEM_PROMPT = """You are a senior Kubernetes security architect with deep expertise in:
- NSA/CISA Kubernetes Hardening Guide
- CIS Kubernetes Benchmark
- MITRE ATT&CK for Containers
- Telco/CNF security (5G core, CNF sidecars, service mesh)
- Supply chain security (image provenance, SBOMs, CVEs)

You have access to tools. Use them methodically:

1. Call load_manifest to parse the YAML and understand what resources are present.
2. Run run_check with check_id='ALL' and resource_index=-1 for a full static sweep.
3. For any container images found, call lookup_image_cves to check for known CVEs.
4. Use report_finding for issues you identify that the static checks did not catch:
   - Logic-level misconfigurations (e.g. overly permissive ingress, insecure inter-service trust)
   - Supply chain risks beyond what static rules cover
   - Missing security annotations (AppArmor, seccomp profiles)
   - Telco/CNF-specific concerns (5G NF sidecars, service mesh misconfig, CNI risks)
   - Combined-risk scenarios where multiple findings compound each other
5. Call finish() when your analysis is complete.

Be thorough but avoid re-running checks you have already completed."""


MAX_ITERATIONS = 25


def analyze_with_agent(
    manifest_path: Path,
    api_key: str,
    verbose: bool = True,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Run the agentic analysis loop.
    Returns (resources, findings).
    """
    client = anthropic.Anthropic(api_key=api_key)

    state: Dict = {
        "resources": [],
        "findings":  [],
        "done":      False,
        "summary":   "",
    }

    messages = [
        {
            "role": "user",
            "content": (
                f"Analyze the Kubernetes manifest at '{manifest_path}' for security misconfigurations. "
                "Be thorough: check all resources, scan container images for CVEs, and report every "
                "finding. Call finish() when done."
            ),
        }
    ]

    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model="claude-sonnet-4-6",
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
