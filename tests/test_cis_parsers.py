# Copyright 2026 Jayden Aung — Apache 2.0
"""
Tests for individual CIS audit parsers.

Each parser is exercised against a recorded kubectl JSON fixture by
monkeypatching the kubectl invocation. No real cluster is required.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cis.parsers.base import ParserError, ParserNotApplicable
from cis.parsers.default_sa import parse_default_sa_automount
from cis.parsers.rbac import parse_rbac_subject_count
from cis.parsers.static_pod_arg import (
    parse_static_pod_arg,
    parse_static_pod_arg_absent,
)


FIXTURES = Path(__file__).parent / "cis_fixtures"


def _ctx():
    return SimpleNamespace(kubeconfig_path=None, cluster_name="test")


def _load(fixture_name: str) -> dict:
    return json.loads((FIXTURES / fixture_name).read_text())


# ── static_pod_arg ────────────────────────────────────────────────────────────

def test_static_pod_arg_returns_value_when_present(monkeypatch):
    from cis.parsers import static_pod_arg as mod
    monkeypatch.setattr(mod, "_kubectl_get",
                        lambda *a, **kw: _load("kube_apiserver_pod_anonymous_auth_false.json"))
    out = parse_static_pod_arg(
        {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
         "container": "kube-apiserver", "arg": "--anonymous-auth"},
        _ctx(),
    )
    assert out.actual_value == "false"
    assert "kube-apiserver" in out.evidence_source


def test_static_pod_arg_returns_none_when_absent(monkeypatch):
    from cis.parsers import static_pod_arg as mod
    monkeypatch.setattr(mod, "_kubectl_get",
                        lambda *a, **kw: _load("kube_apiserver_pod_anonymous_auth_false.json"))
    out = parse_static_pod_arg(
        {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
         "container": "kube-apiserver", "arg": "--nonexistent-flag"},
        _ctx(),
    )
    assert out.actual_value is None


def test_static_pod_arg_raises_not_applicable_on_empty_pod_list(monkeypatch):
    from cis.parsers import static_pod_arg as mod
    monkeypatch.setattr(mod, "_kubectl_get", lambda *a, **kw: _load("empty_pod_list.json"))
    with pytest.raises(ParserNotApplicable):
        parse_static_pod_arg(
            {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
             "container": "kube-apiserver", "arg": "--anonymous-auth"},
            _ctx(),
        )


def test_static_pod_arg_absent_translates(monkeypatch):
    from cis.parsers import static_pod_arg as mod
    monkeypatch.setattr(mod, "_kubectl_get",
                        lambda *a, **kw: _load("kube_apiserver_pod_anonymous_auth_false.json"))
    out_present = parse_static_pod_arg_absent(
        {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
         "container": "kube-apiserver", "arg": "--anonymous-auth"},
        _ctx(),
    )
    assert out_present.actual_value == "present"

    out_absent = parse_static_pod_arg_absent(
        {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
         "container": "kube-apiserver", "arg": "--token-auth-file"},
        _ctx(),
    )
    assert out_absent.actual_value == "absent"


# ── rbac_subject_count ────────────────────────────────────────────────────────

def test_rbac_subject_count_excludes_bootstrap_by_default(monkeypatch):
    from cis.parsers import rbac as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    out = parse_rbac_subject_count({"role_ref": "cluster-admin"}, _ctx())
    # Fixture has 2 non-bootstrap subjects (deployer SA, alice user).
    assert out.actual_value == "2"
    assert "deployer" in out.evidence_source or "alice" in out.evidence_source


def test_rbac_subject_count_can_include_bootstrap(monkeypatch):
    from cis.parsers import rbac as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    out = parse_rbac_subject_count(
        {"role_ref": "cluster-admin", "exclude_bootstrap": False}, _ctx()
    )
    # Now includes the system:masters subject too -> 3.
    assert out.actual_value == "3"


def test_rbac_subject_count_unknown_role(monkeypatch):
    from cis.parsers import rbac as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("cluster_role_bindings.json"))
    out = parse_rbac_subject_count({"role_ref": "nonexistent-role"}, _ctx())
    assert out.actual_value == "0"


# ── default_sa_automount ──────────────────────────────────────────────────────

def test_default_sa_automount_detects_offenders(monkeypatch):
    from cis.parsers import default_sa as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_offending.json"))
    out = parse_default_sa_automount({}, _ctx())
    assert out.actual_value == "true"  # offenders exist
    assert "default" in out.evidence_source or "app-prod" in out.evidence_source


def test_default_sa_automount_passes_when_clean(monkeypatch):
    from cis.parsers import default_sa as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_clean.json"))
    out = parse_default_sa_automount({}, _ctx())
    assert out.actual_value == "false"


def test_default_sa_skips_system_namespaces(monkeypatch):
    """kube-system 'default' SA without automount: false should not be an offender."""
    from cis.parsers import default_sa as mod
    monkeypatch.setattr(mod, "_kubectl_get_json",
                        lambda *a, **kw: _load("serviceaccounts_clean.json"))
    out = parse_default_sa_automount({"include_system_namespaces": False}, _ctx())
    assert out.actual_value == "false"


# ── parser error propagation ──────────────────────────────────────────────────

def test_kubectl_missing_raises_parser_error(monkeypatch):
    from cis.parsers import static_pod_arg as mod

    def boom(*a, **kw):
        raise FileNotFoundError("kubectl: not found")

    monkeypatch.setattr(mod.subprocess, "run", boom)
    with pytest.raises(ParserError):
        parse_static_pod_arg(
            {"namespace": "kube-system", "label_selector": "component=kube-apiserver",
             "container": "kube-apiserver", "arg": "--anonymous-auth"},
            _ctx(),
        )
