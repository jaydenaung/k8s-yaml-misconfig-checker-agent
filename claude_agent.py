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

from tools import build_tools, execute_tool

DEFAULT_MODEL = os.environ.get("K8S_CHECKER_MODEL", "claude-sonnet-4-6")

# NOTE: Prompt injection risk — malicious YAML files could embed text attempting to
# override these instructions. The tool_use API reduces (but does not eliminate) this
# risk. Never load YAML from untrusted sources without reviewing it first.
_SYSTEM_PROMPT_BASE = """You are a senior Kubernetes security architect with deep expertise in:
- NSA/CISA Kubernetes Hardening Guide
- CIS Kubernetes Benchmark
- MITRE ATT&CK for Containers
- Cloud-native workload security (CNF, service mesh, DPDK, CNI)
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

**Service account probing:**
- After finding auto-mounted SA tokens (K8S-008) or suspicious RBAC bindings (K8S-014),
  call probe_service_account to confirm what the SA can actually access at runtime.
- Use the SA name and namespace from the manifest or cluster query.
- If probe confirms dangerous access (secrets, configmaps, cluster-wide resources):
  - Call report_finding with check_id="SAP-001", source reflected in detail, and the
    confirmed_access list in the detail field. Set severity to CRITICAL if secrets are
    accessible, HIGH otherwise.
- This turns a theoretical static finding into a runtime-proven exploit path.

**AI findings:**
- Use report_finding for issues the static checks did not catch:
  - Logic-level misconfigurations (insecure inter-service trust, permissive ingress)
  - Supply chain risks beyond static rules
  - Missing AppArmor / seccomp annotations
  - Cloud-native concerns (service mesh misconfig, CNF sidecars, DPDK, CNI)
  - Compound-risk chains where multiple findings amplify each other
  - Runtime vs declared state mismatches

**Compound risk correlation:**
- After probe_service_account, call scan_cluster_images to get CVE data for running images.
- Correlate signals across each pod:
    CVE signal:             image has critical or high CVEs
    Misconfiguration signal: pod has CRITICAL/HIGH static findings (privileged, root, hostPID…)
    RBAC signal:            SA has confirmed dangerous access (from probe_service_account)
    Network signal:         pod's namespace has no NetworkPolicy
- If a pod has 2 or more signals, call report_finding with check_id="CMP-001" (or CMP-002
  for 3 signals, CMP-003 for 4), severity=CRITICAL if CVE+RBAC or CVE+misconfig+network,
  else HIGH. In the detail field, list every signal with specifics. In attack_scenario,
  write the full exploit chain: "attacker exploits CVE → escapes container → uses SA token
  to exfiltrate secrets".

**Finishing:**
- Call finish() when analysis is complete

Be thorough but avoid re-running checks you have already completed."""

SYSTEM_PROMPT = _SYSTEM_PROMPT_BASE

_PATCH_GEN_SYSTEM = (
    "You are a Kubernetes security engineer. "
    "For each finding provided, call suggest_patch with a minimal YAML snippet that corrects the issue. "
    "patch_yaml must include just the changed field(s) with enough parent-key context to be unambiguous. "
    "explanation must be one sentence on what changed and why. "
    "Call finish() when all patches have been generated."
)


MAX_ITERATIONS = 25

# Pricing for claude-sonnet-4-6 (USD per token)
_PRICING = {
    "input":        3.00 / 1_000_000,
    "output":      15.00 / 1_000_000,
    "cache_write":  3.75 / 1_000_000,
    "cache_read":   0.30 / 1_000_000,
}


def _cost(usage: Dict) -> float:
    return (
        usage.get("input_tokens", 0)          * _PRICING["input"] +
        usage.get("output_tokens", 0)         * _PRICING["output"] +
        usage.get("cache_creation_tokens", 0) * _PRICING["cache_write"] +
        usage.get("cache_read_tokens", 0)     * _PRICING["cache_read"]
    )


def _cached(text: str) -> list:
    """Wrap a system prompt string for prompt caching."""
    return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]


def _accum(usage: Dict, response) -> None:
    """Accumulate token counts from an API response into a usage dict."""
    u = response.usage
    usage["input_tokens"]          += getattr(u, "input_tokens", 0)
    usage["output_tokens"]         += getattr(u, "output_tokens", 0)
    usage["cache_creation_tokens"] += getattr(u, "cache_creation_input_tokens", 0)
    usage["cache_read_tokens"]     += getattr(u, "cache_read_input_tokens", 0)


_SCAN_TOOLS = build_tools(patch_enabled=False)   # patches are always post-scan
_PATCH_TOOLS = build_tools(patch_enabled=True)    # only used by generate_patches_for_findings


def analyze_cluster_with_agent(
    cluster_name: str,
    kubeconfig_path: Path,
    api_key: str,
    verbose: bool = False,
    model: str = None,
    event_callback=None,
) -> Tuple[List[Dict], List[Dict], Dict]:
    """Agentic analysis of a live cluster. Returns (resources, findings, token_usage)."""
    client = anthropic.Anthropic(api_key=api_key, max_retries=3)
    model = model or DEFAULT_MODEL

    state: Dict = {
        "resources":       [],
        "findings":        [],
        "done":            False,
        "summary":         "",
        "kubeconfig_path": str(kubeconfig_path),
    }
    usage: Dict = {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0}

    messages = [
        {
            "role": "user",
            "content": (
                f"Analyze cluster '{cluster_name}' for Kubernetes security misconfigurations. "
                "Use query_cluster with namespace='all' where applicable to inspect: "
                "pods, deployments, clusterroles, clusterrolebindings, rolebindings, "
                "networkpolicies, secrets, serviceaccounts. "
                "Report every finding with report_finding. Pay special attention to: "
                "privileged containers, wildcard RBAC, missing NetworkPolicies, "
                "service accounts with excessive permissions, containers running as root, "
                "and hostPath volume mounts. Call finish() when complete."
            ),
        }
    ]

    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_cached(SYSTEM_PROMPT),
            tools=_SCAN_TOOLS,
            messages=messages,
        )
        _accum(usage, response)
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
                if event_callback:
                    event_callback(_make_event(block.name, block.input))
                result = execute_tool(block.name, block.input, state)
                result_json = json.dumps(result)
                if len(result_json) > 8000:
                    result_json = result_json[:8000] + "\n...[truncated — response too large]"
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result_json,
                })

        messages.append({"role": "user", "content": tool_results})

        if state.get("done"):
            break

    usage["estimated_cost_usd"] = _cost(usage)
    return state["resources"], state["findings"], usage


def analyze_with_agent(
    manifest_path: Path,
    api_key: str,
    verbose: bool = True,
    model: str = None,
    event_callback=None,
) -> Tuple[List[Dict], List[Dict], Dict]:
    """Agentic manifest analysis. Returns (resources, findings, token_usage)."""
    client = anthropic.Anthropic(api_key=api_key, max_retries=3)
    model = model or DEFAULT_MODEL

    state: Dict = {
        "resources": [],
        "findings":  [],
        "done":      False,
        "summary":   "",
    }
    usage: Dict = {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0}

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
            system=_cached(SYSTEM_PROMPT),
            tools=_SCAN_TOOLS,
            messages=messages,
        )
        _accum(usage, response)
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
                if event_callback:
                    event_callback(_make_event(block.name, block.input))
                result = execute_tool(block.name, block.input, state)
                result_json = json.dumps(result)
                if len(result_json) > 8000:
                    result_json = result_json[:8000] + "\n...[truncated — response too large]"
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result_json,
                })

        messages.append({"role": "user", "content": tool_results})

        if state.get("done"):
            break

    usage["estimated_cost_usd"] = _cost(usage)
    return state["resources"], state["findings"], usage


def generate_patches_for_findings(
    findings: List[Dict],
    api_key: str,
    verbose: bool = False,
    model: str = None,
) -> Tuple[List[Dict], Dict]:
    """
    Post-scan patch generation. Returns (findings_with_patches, token_usage).
    """
    unpatched = [f for f in findings if not f.get("suggested_patch")]
    if not unpatched:
        return findings, {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0, "estimated_cost_usd": 0.0}

    client = anthropic.Anthropic(api_key=api_key, max_retries=3)
    model = model or DEFAULT_MODEL

    state: Dict = {"resources": [], "findings": list(findings), "done": False, "summary": ""}
    usage: Dict = {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0}

    patch_only_tools = [t for t in _PATCH_TOOLS if t["name"] in ("suggest_patch", "finish")]

    findings_summary = "\n".join(
        f"- [{f.get('check_id','?')}] {f.get('context','?')}: {f.get('title','?')} ({f.get('severity','?')})"
        for f in unpatched
    )

    messages = [{
        "role": "user",
        "content": (
            f"Generate corrected YAML patches for each of the {len(unpatched)} findings below. "
            "For each, call suggest_patch with the same check_id and context as the finding, "
            "a minimal patch_yaml snippet (just the changed field(s) with parent-key context), "
            "and a one-sentence explanation. Call finish() when all patches are generated.\n\n"
            f"FINDINGS:\n{findings_summary}"
        ),
    }]

    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_cached(_PATCH_GEN_SYSTEM),
            tools=patch_only_tools,
            messages=messages,
        )
        _accum(usage, response)
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason in ("end_turn",):
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

    usage["estimated_cost_usd"] = _cost(usage)
    return state["findings"], usage


_ENRICH_SYSTEM = (
    "You are a Kubernetes security architect. "
    "For each finding, call enrich_finding with a concrete attack_scenario "
    "(1-3 sentences: how an attacker exploits this specific misconfiguration, referencing the context). "
    "Call finish() when all findings have been enriched."
)

_ENRICH_TOOLS = [
    {
        "name": "enrich_finding",
        "description": "Add a concrete attack_scenario to a finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "check_id":        {"type": "string"},
                "context":         {"type": "string"},
                "attack_scenario": {"type": "string", "description": "1-3 sentences: concrete attacker exploit chain for this misconfiguration."},
            },
            "required": ["check_id", "context", "attack_scenario"],
        },
    },
    {
        "name": "finish",
        "description": "Signal that all findings have been enriched.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


def enrich_findings_with_ai(
    findings: List[Dict],
    api_key: str,
    model: str = None,
) -> Tuple[List[Dict], Dict]:
    """
    Post-scan AI enrichment. Returns (enriched_findings, token_usage).
    """
    to_enrich = [f for f in findings if not f.get("attack_scenario")]
    if not to_enrich:
        return findings, {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0, "estimated_cost_usd": 0.0}

    client = anthropic.Anthropic(api_key=api_key, max_retries=3)
    model = model or DEFAULT_MODEL

    enriched: Dict[tuple, Dict] = {}
    for f in findings:
        enriched[(f.get("check_id"), f.get("context"))] = f

    usage: Dict = {"input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0, "cache_read_tokens": 0}

    summary = "\n".join(
        f"- [{f.get('check_id','?')}] {f.get('context','?')}: {f.get('title','?')} "
        f"({f.get('severity','?')}) — {(f.get('detail') or '')[:120]}"
        for f in to_enrich
    )

    messages = [{
        "role": "user",
        "content": (
            f"Enrich each of the {len(to_enrich)} Kubernetes security findings below. "
            "For each, call enrich_finding with the same check_id and context as listed "
            "and a concrete attack_scenario (how an attacker exploits this specific issue). "
            "Call finish() when done.\n\n"
            f"FINDINGS:\n{summary}"
        ),
    }]

    done = False
    for _ in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_cached(_ENRICH_SYSTEM),
            tools=_ENRICH_TOOLS,
            messages=messages,
        )
        _accum(usage, response)
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break
        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            if block.name == "finish":
                done = True
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": '{"ok":true}'})
                break
            elif block.name == "enrich_finding":
                inp = block.input
                key = (inp.get("check_id"), inp.get("context"))
                if key in enriched:
                    enriched[key]["attack_scenario"] = inp.get("attack_scenario")
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": '{"ok":true}'})

        messages.append({"role": "user", "content": tool_results})
        if done:
            break

    usage["estimated_cost_usd"] = _cost(usage)
    return list(enriched.values()), usage


_TOOL_ICONS = {
    "load_manifest":         "📂",
    "render_helm_chart":     "⎈",
    "query_cluster":         "🌐",
    "run_check":             "🔍",
    "lookup_image_cves":     "🛡",
    "report_finding":        "⚠️",
    "probe_service_account": "🔑",
    "scan_cluster_images":   "🔬",
    "suggest_patch":         "🔧",
    "finish":                "✅",
}


def _format_detail(name: str, input_data: Dict) -> str:
    if name == "run_check":
        return f"check={input_data.get('check_id')}  resource={input_data.get('resource_index')}"
    if name == "lookup_image_cves":
        return input_data.get("image", "")
    if name == "report_finding":
        return f"[{input_data.get('severity')}] {input_data.get('title', '')}"
    if name == "probe_service_account":
        return f"{input_data.get('service_account')} ({input_data.get('namespace')})"
    if name == "scan_cluster_images":
        return f"namespace={input_data.get('namespace', 'all')}"
    if name == "suggest_patch":
        return f"[{input_data.get('check_id')}] {input_data.get('context', '')}"
    if name == "finish":
        return (input_data.get("summary") or "")[:80]
    return str(input_data)[:80]


def _make_event(name: str, input_data: Dict) -> Dict:
    """Build an SSE event dict for a single tool call."""
    if name == "report_finding":
        return {
            "type":     "finding",
            "severity": input_data.get("severity", "INFO"),
            "title":    input_data.get("title", ""),
            "icon":     "⚠️",
        }
    return {
        "type":   "tool_call",
        "tool":   name,
        "icon":   _TOOL_ICONS.get(name, "🔧"),
        "detail": _format_detail(name, input_data),
    }


def _log_tool_call(name: str, input_data: Dict) -> None:
    icon = _TOOL_ICONS.get(name, "🔧")
    print(f"      {icon}  {name}({_format_detail(name, input_data)})")
