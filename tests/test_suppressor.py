"""
Unit tests for suppressor.py
"""

from suppressor import apply_suppressions


def finding(check_id, context="Deployment/app", severity="HIGH"):
    return {
        "check_id": check_id,
        "context": context,
        "severity": severity,
        "title": f"Test finding {check_id}",
        "source": "static",
    }


# ── apply_suppressions ────────────────────────────────────────────────────────

def test_no_suppressions_returns_all_active():
    findings = [finding("K8S-001"), finding("K8S-002")]
    active, suppressed = apply_suppressions(findings, [])
    assert len(active) == 2
    assert len(suppressed) == 0


def test_check_id_match_suppresses_finding():
    findings = [finding("K8S-008")]
    rules = [{"check_id": "K8S-008", "reason": "Accepted risk"}]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(active) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppressed_reason"] == "Accepted risk"


def test_check_id_no_match_leaves_finding_active():
    findings = [finding("K8S-001")]
    rules = [{"check_id": "K8S-008"}]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(active) == 1
    assert len(suppressed) == 0


def test_resource_scoped_suppression_matches():
    findings = [finding("K8S-007", context="Deployment/legacy")]
    rules = [{"check_id": "K8S-007", "resource": "Deployment/legacy", "reason": "OK"}]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(suppressed) == 1


def test_resource_scoped_suppression_does_not_match_other_resource():
    findings = [
        finding("K8S-007", context="Deployment/legacy"),
        finding("K8S-007", context="Deployment/new-app"),
    ]
    rules = [{"check_id": "K8S-007", "resource": "Deployment/legacy"}]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(active) == 1
    assert active[0]["context"] == "Deployment/new-app"
    assert len(suppressed) == 1


def test_global_rule_suppresses_all_matching_check_id():
    findings = [
        finding("K8S-012", context="Deployment/app-a"),
        finding("K8S-012", context="Deployment/app-b"),
    ]
    rules = [{"check_id": "K8S-012", "reason": "No HTTP endpoints"}]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(active) == 0
    assert len(suppressed) == 2


def test_multiple_rules_suppress_independently():
    findings = [finding("K8S-001"), finding("K8S-002"), finding("K8S-003")]
    rules = [
        {"check_id": "K8S-001", "reason": "r1"},
        {"check_id": "K8S-003", "reason": "r3"},
    ]
    active, suppressed = apply_suppressions(findings, rules)
    assert len(active) == 1
    assert active[0]["check_id"] == "K8S-002"
    assert len(suppressed) == 2


def test_suppressed_finding_preserves_original_fields():
    f = finding("K8S-008")
    _, suppressed = apply_suppressions([f], [{"check_id": "K8S-008", "reason": "test"}])
    assert suppressed[0]["severity"] == "HIGH"
    assert suppressed[0]["source"] == "static"
    assert suppressed[0]["suppressed_reason"] == "test"
