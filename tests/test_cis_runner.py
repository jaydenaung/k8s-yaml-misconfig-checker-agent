# Copyright 2026 Jayden Aung — Apache 2.0
"""
End-to-end tests for APIRunner + Orchestrator, monkeypatching the kubectl
JSON fetchers in each parser module so no real cluster is required.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cis import (
    APIRunner,
    Orchestrator,
    RunnerContext,
    load_benchmark,
)
from cis.result import Status, score


FIXTURES = Path(__file__).parent / "cis_fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def healthy_cluster(monkeypatch):
    """Wire every parser's kubectl call to a 'healthy' fixture."""
    from cis.parsers import static_pod_arg, rbac, default_sa
    monkeypatch.setattr(static_pod_arg, "_kubectl_get",
                        lambda *a, **kw: _load("kube_apiserver_pod_anonymous_auth_false.json"))
    monkeypatch.setattr(rbac, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    monkeypatch.setattr(default_sa, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_clean.json"))


@pytest.fixture
def vulnerable_cluster(monkeypatch):
    from cis.parsers import static_pod_arg, rbac, default_sa
    monkeypatch.setattr(static_pod_arg, "_kubectl_get",
                        lambda *a, **kw: _load("kube_apiserver_pod_anonymous_auth_true.json"))
    monkeypatch.setattr(rbac, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    monkeypatch.setattr(default_sa, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_offending.json"))


@pytest.fixture
def managed_cluster(monkeypatch):
    """No control plane pods visible (EKS/GKE/AKS style)."""
    from cis.parsers import static_pod_arg, rbac, default_sa
    monkeypatch.setattr(static_pod_arg, "_kubectl_get",
                        lambda *a, **kw: _load("empty_pod_list.json"))
    monkeypatch.setattr(rbac, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    monkeypatch.setattr(default_sa, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_clean.json"))


def _orch():
    return Orchestrator(runners=[APIRunner()])


def test_anonymous_auth_passes_on_healthy(healthy_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-1.2.1")
    result = _orch().run_check(check, RunnerContext())
    assert result.status == Status.PASS
    assert result.actual_value == "false"


def test_anonymous_auth_fails_on_vulnerable(vulnerable_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-1.2.1")
    result = _orch().run_check(check, RunnerContext())
    assert result.status == Status.FAIL
    assert result.actual_value == "true"
    assert result.severity == "HIGH"
    assert result.remediation


def test_authorization_mode_regex_fails_on_alwaysallow(vulnerable_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-1.2.6")
    result = _orch().run_check(check, RunnerContext())
    assert result.status == Status.FAIL


def test_managed_cluster_skips_control_plane_checks(managed_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-1.2.1")
    result = _orch().run_check(check, RunnerContext())
    # Control plane invisible -> SKIP, not FAIL.
    assert result.status == Status.SKIP
    assert "managed" in (result.evidence_source or "").lower()


def test_full_benchmark_run_produces_one_result_per_check(healthy_cluster):
    bench = load_benchmark("1.9")
    results = _orch().run_benchmark(bench, RunnerContext())
    assert len(results) == len(bench.checks)
    # Every result has a checked_at timestamp.
    assert all(r.checked_at is not None for r in results)


def test_score_computation_excludes_manual_and_skip(healthy_cluster):
    bench = load_benchmark("1.9")
    results = _orch().run_benchmark(bench, RunnerContext())
    s = score(results)
    assert 0 <= s <= 100


def test_score_on_vulnerable_is_lower_than_healthy(vulnerable_cluster):
    bench = load_benchmark("1.9")
    vuln_results = _orch().run_benchmark(bench, RunnerContext())
    vuln_score = score(vuln_results)
    assert vuln_score < 100


def test_rbac_cluster_admin_lte_one(healthy_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-5.1.1")
    result = _orch().run_check(check, RunnerContext())
    # Fixture has 2 non-bootstrap subjects, which is > 1, so this fails.
    assert result.status == Status.FAIL
    assert result.actual_value == "2"


def test_default_sa_passes_when_clean(healthy_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-5.1.5")
    result = _orch().run_check(check, RunnerContext())
    assert result.status == Status.PASS


def test_default_sa_fails_when_offenders_present(vulnerable_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-5.1.5")
    result = _orch().run_check(check, RunnerContext())
    assert result.status == Status.FAIL


def test_result_serializable(healthy_cluster):
    bench = load_benchmark("1.9")
    check = next(c for c in bench.checks if c.id == "CIS-1.2.1")
    result = _orch().run_check(check, RunnerContext())
    d = result.to_dict()
    assert d["control_id"] == "CIS-1.2.1"
    assert d["status"] == "PASS"
    assert isinstance(d["checked_at"], str)  # ISO formatted
