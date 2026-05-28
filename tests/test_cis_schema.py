# Copyright 2026 Jayden Aung — Apache 2.0
"""Tests for the CIS schema loader and dataclasses."""

import pytest

from cis.schema import Audit, Benchmark, CheckDefinition, Expected, load_benchmark


def test_benchmark_loads():
    b = load_benchmark("1.9")
    assert isinstance(b, Benchmark)
    assert b.version == "1.9"
    assert "1.29" in b.target_k8s_versions
    assert len(b.checks) == 20


def test_every_check_has_required_fields():
    b = load_benchmark("1.9")
    for c in b.checks:
        assert c.id.startswith("CIS-")
        assert c.title
        assert c.section
        assert c.profile in ("control-plane", "worker", "policies")
        assert c.tier in ("api", "node", "logical")
        assert c.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert isinstance(c.audit, Audit)
        assert isinstance(c.expected, Expected)


def test_audit_params_preserved():
    b = load_benchmark("1.9")
    cis_1_2_1 = next(c for c in b.checks if c.id == "CIS-1.2.1")
    assert cis_1_2_1.audit.type == "static_pod_arg"
    assert cis_1_2_1.audit.params["container"] == "kube-apiserver"
    assert cis_1_2_1.audit.params["arg"] == "--anonymous-auth"


def test_by_profile():
    b = load_benchmark("1.9")
    control_plane = b.by_profile("control-plane")
    policies = b.by_profile("policies")
    assert len(control_plane) + len(policies) == len(b.checks)
    assert all(c.profile == "control-plane" for c in control_plane)
    assert all(c.profile == "policies" for c in policies)


def test_unknown_version_raises():
    with pytest.raises(FileNotFoundError):
        load_benchmark("0.0")


def test_check_definitions_are_frozen():
    """Dataclasses are frozen to prevent runtime mutation of benchmark data."""
    b = load_benchmark("1.9")
    check = b.checks[0]
    with pytest.raises(Exception):  # FrozenInstanceError
        check.severity = "LOW"
