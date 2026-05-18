# Contributing to KubeSentinel

Thank you for contributing! This document covers how to add new static checks,
new agent tools, run tests, and submit pull requests.

## Setup

```bash
git clone https://github.com/jaydenaung/kubesentinel.git
cd kubesentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Running tests

```bash
pytest tests/ -v
```

All checks in `analyzer.py` have unit tests in `tests/test_analyzer.py`. Add tests
alongside any new check you write.

## Adding a static check

Static checks live in `analyzer.py`. Each check is a plain function:

```python
def check_my_new_rule(resource: Dict, context: str):
    findings = []
    # inspect the resource dict
    if some_condition:
        findings.append(_finding(
            check_id="K8S-015",
            severity="HIGH",          # CRITICAL | HIGH | MEDIUM | LOW | INFO
            context=context,
            title="Short title",
            detail="What is wrong and why it matters.",
            remediation="Specific steps to fix it.",
            resource_path="spec.path.to.field",
        ))
    return findings
```

Then register it in two places:

1. Add it to the `fns` list inside `run_static_checks()`.
2. Add it to `CHECK_REGISTRY` with the next available ID.

Finally, add a test in `tests/test_analyzer.py` covering at least one positive case
(finding detected) and one negative case (no finding).

## Adding an agent tool

Agent tools live in `tools.py`.

1. Add the tool schema to the `TOOLS` list:

```python
{
    "name": "my_tool",
    "description": "What this tool does and when Claude should call it.",
    "input_schema": {
        "type": "object",
        "properties": {
            "param": {"type": "string", "description": "..."}
        },
        "required": ["param"]
    }
}
```

2. Add an execution function:

```python
def _my_tool(input_data: Dict, state: Dict) -> Dict:
    # do the work
    return {"result": ...}
```

3. Wire it into `execute_tool()`:

```python
"my_tool": _my_tool,
```

Claude will automatically start calling your tool once it appears in the `TOOLS` list.

## Pull request checklist

- [ ] New static checks include a `CHECK_REGISTRY` entry and unit tests
- [ ] New tools include an execution function wired into `execute_tool()`
- [ ] `pytest tests/` passes with no failures
- [ ] No secrets or `.env` files committed

## Severity guide

| Severity | When to use |
|----------|-------------|
| CRITICAL | Direct path to container escape or cluster takeover |
| HIGH | Significant privilege escalation or data exposure risk |
| MEDIUM | Weakens defence-in-depth; exploitable under certain conditions |
| LOW | Best-practice deviation with limited direct impact |
| INFO | Informational; no immediate security risk |
