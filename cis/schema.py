# Copyright 2026 Jayden Aung — Apache 2.0
"""
cis/schema.py — Dataclass models for benchmark check definitions.

The schema is intentionally additive: `audit.type` and `expected.operator` are
string identifiers, and each new check kind ships as a new parser + a new
type identifier without breaking existing benchmark files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


_BENCHMARKS_DIR = Path(__file__).parent / "benchmarks"


@dataclass(frozen=True)
class Audit:
    """How a check determines the observed value."""
    type: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Expected:
    """How the observed value is compared against the expected outcome."""
    operator: str
    value: Optional[str] = None
    values: Optional[List[str]] = None


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    title: str
    section: str
    scored: bool
    level: int
    profile: str           # control-plane | worker | policies
    tier: str              # api | node | logical
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    audit: Audit
    expected: Expected
    remediation: str
    references: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Benchmark:
    version: str
    title: str
    target_k8s_versions: List[str]
    checks: List[CheckDefinition]

    def by_profile(self, profile: str) -> List[CheckDefinition]:
        return [c for c in self.checks if c.profile == profile]


def _parse_audit(raw: Dict[str, Any]) -> Audit:
    audit_type = raw.pop("type")
    return Audit(type=audit_type, params=raw)


def _parse_expected(raw: Dict[str, Any]) -> Expected:
    return Expected(
        operator=raw["operator"],
        value=raw.get("value"),
        values=raw.get("values"),
    )


def _parse_check(raw: Dict[str, Any]) -> CheckDefinition:
    return CheckDefinition(
        id=raw["id"],
        title=raw["title"],
        section=raw["section"],
        scored=raw.get("scored", True),
        level=raw.get("level", 1),
        profile=raw["profile"],
        tier=raw["tier"],
        severity=raw.get("severity", "MEDIUM"),
        audit=_parse_audit(dict(raw["audit"])),
        expected=_parse_expected(raw["expected"]),
        remediation=raw.get("remediation", "").strip(),
        references=raw.get("references", {}) or {},
    )


def load_benchmark(version: str = "1.9") -> Benchmark:
    """
    Load a CIS Kubernetes benchmark by version.

    Versions correspond to files in cis/benchmarks/, e.g. cis_kubernetes_1_9.yaml.
    """
    filename = f"cis_kubernetes_{version.replace('.', '_')}.yaml"
    path = _BENCHMARKS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Benchmark not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    return Benchmark(
        version=str(data["version"]),
        title=data["title"],
        target_k8s_versions=list(data.get("target_k8s_versions", [])),
        checks=[_parse_check(c) for c in data["checks"]],
    )
