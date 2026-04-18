# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
claude_agent.py — AI-powered analysis layer using Anthropic API

Sends the manifest + static findings to Claude for:
  - Deeper contextual analysis
  - Supply chain risk assessment
  - Telco/CNF-specific risk scoring
  - Plain-English attack narrative
  - Remediation priority ordering
"""

import json
import yaml
import anthropic
from typing import List, Dict


SYSTEM_PROMPT = """You are a senior Kubernetes security architect specializing in cloud-native 
security, telco/CNF deployments, and container security. You have deep expertise in the 
NSA/CISA Kubernetes Hardening Guide, CIS Kubernetes Benchmark, and MITRE ATT&CK for Containers.

When analyzing Kubernetes manifests, you:
1. Identify security misconfigurations the static rules may have missed
2. Assess the realistic attack impact in a telco/cloud-native context
3. Identify supply chain and runtime risks
4. Provide a concise, prioritized remediation plan

Always respond in valid JSON only. No markdown, no prose outside the JSON structure."""


ANALYSIS_PROMPT = """Analyze this Kubernetes manifest for security misconfigurations.

## Manifest YAML:
{yaml_content}

## Static analysis already found these issues:
{static_findings}

Respond with a JSON array of additional findings NOT already covered by static analysis.
Each finding must follow this exact structure:
{{
  "source": "claude-ai",
  "check_id": "AI-NNN",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "context": "<Kind/name>",
  "title": "<short title>",
  "detail": "<what the problem is and why it matters>",
  "remediation": "<specific fix>",
  "resource_path": "<yaml path if applicable>",
  "attack_scenario": "<one sentence describing how an attacker would exploit this>",
  "telco_relevance": "<HIGH|MEDIUM|LOW — with one sentence explaining relevance to telco/CNF workloads>"
}}

Focus on:
- Logic-level issues static rules can't catch (e.g. misconfigured ingress rules, insecure inter-service trust)
- Supply chain risks in image references
- Missing security annotations (AppArmor, seccomp)
- Overall attack surface narrative
- Any telco/CNF-specific concerns (5G core, CNF sidecars, service mesh misconfig)

If no additional findings, return an empty array [].
Return ONLY the JSON array. No other text."""


def analyze_with_claude(
    resources: List[Dict],
    static_findings: List[Dict],
    api_key: str
) -> List[Dict]:
    """Send manifest and static findings to Claude for deeper analysis."""

    client = anthropic.Anthropic(api_key=api_key)

    # Serialize resources back to YAML for Claude to read naturally
    yaml_content = yaml.dump_all(resources, default_flow_style=False)

    # Summarize static findings compactly
    static_summary = []
    for f in static_findings:
        static_summary.append({
            "check_id": f["check_id"],
            "severity": f["severity"],
            "title": f["title"],
            "context": f["context"],
        })

    prompt = ANALYSIS_PROMPT.format(
        yaml_content=yaml_content,
        static_findings=json.dumps(static_summary, indent=2)
    )

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response_text = message.content[0].text.strip()

        # Strip accidental markdown fences if present
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        findings = json.loads(response_text)

        # Ensure all findings have required fields
        for f in findings:
            f.setdefault("source", "claude-ai")
            f.setdefault("resource_path", "")
            f.setdefault("attack_scenario", "")
            f.setdefault("telco_relevance", "")

        return findings

    except json.JSONDecodeError as e:
        print(f"      [WARN] Could not parse Claude response as JSON: {e}")
        return []
    except anthropic.APIError as e:
        print(f"      [WARN] Anthropic API error: {e}")
        return []
    except Exception as e:
        print(f"      [WARN] Unexpected error during AI analysis: {e}")
        return []
