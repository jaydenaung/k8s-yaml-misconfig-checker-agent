# KubeSentinel — AI-powered Kubernetes Security Agent by Jayden Aung

A true AI security agent for Kubernetes manifests. Claude drives the analysis using the
Anthropic tool_use API — deciding which checks to run, scanning images for CVEs, querying
live clusters, and identifying compound risk scenarios that static rules alone cannot catch.

## How it works

Instead of a fixed pipeline, Claude acts as an autonomous agent with tools:

```
📂 load_manifest       → parse a YAML file or entire directory of manifests
⎈  render_helm_chart   → render a Helm chart via helm template, then analyze
🌐 query_cluster       → inspect a live cluster: pods, RBAC, NetworkPolicies, Secrets
🔍 run_check           → run static security checks (individual or all 14)
🛡 lookup_image_cves   → scan container images for CVEs via Trivy
⚠  report_finding      → record AI-identified findings
✅ finish              → end analysis, emit report
```

Claude decides the order and depth of investigation based on what it finds.

## Features

- **Agentic loop** — Claude calls tools iteratively, not a one-shot prompt
- **14 static checks** covering CIS Benchmark, NSA/CISA hardening guide, OWASP K8s Top 10
- **Live cluster analysis** — inspect running pods, RBAC bindings, and NetworkPolicies via `kubectl`
- **Directory scanning** — scan an entire folder of manifests in one command
- **Helm chart support** — render charts with `helm template` before analysis
- **CVE scanning** via Trivy for container images (optional)
- **Suppression allowlist** — acknowledge accepted risks with `.k8s-checker-ignore.yaml`
- **AI-identified findings** — logic-level issues, compound risk chains, telco/CNF-specific concerns
- **Markdown report** with severity table, risk score, and remediation priority ordering
- **CI/CD friendly** — exit code `2` on CRITICAL findings
- **48 unit tests** covering all static checks and suppression logic
- **Configurable model** via `--model` flag or `K8S_CHECKER_MODEL` env var

## Quick start

```bash
# 1. Clone the repo
git clone https://github.com/jaydenaung/kubesentinel.git
cd kubesentinel

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

# 3. Install dependencies
# Use python -m pip to guarantee packages install into the active venv
python -m pip install -r requirements.txt

# 4. Set your Anthropic API key
cp .env.example .env
# Edit .env and add your key — or export it directly:
export ANTHROPIC_API_KEY=your-key-here

# 5. Run the agent
python agent.py samples/vulnerable.yaml          # single file
python agent.py k8s/                             # entire directory
python agent.py ./my-helm-chart/                 # Helm chart
python agent.py samples/vulnerable.yaml --output reports/result.md

# Static checks only — no API key required
python agent.py samples/vulnerable.yaml --no-ai

# Raw JSON output — useful for piping to other tools
python agent.py samples/vulnerable.yaml --json

# Use a specific model
python agent.py samples/vulnerable.yaml --model claude-haiku-4-5-20251001
```

## Configuration

| Method | Example |
|--------|---------|
| `.env` file | `ANTHROPIC_API_KEY=sk-ant-...` |
| Environment variable | `export ANTHROPIC_API_KEY=sk-ant-...` |
| Model override (CLI) | `--model claude-haiku-4-5-20251001` |
| Model override (env) | `K8S_CHECKER_MODEL=claude-haiku-4-5-20251001` |

Default model: `claude-sonnet-4-6`

## Suppressing known / accepted findings

Create a `.k8s-checker-ignore.yaml` file next to your manifest (or in the project root)
to silence findings your team has reviewed and accepted. Suppressed findings still appear
in the report footer with their reasons for auditability.

```yaml
# .k8s-checker-ignore.yaml
suppress:
  - check_id: K8S-008
    resource: Deployment/legacy-api
    reason: "Migrating off auto-mounted SA tokens in Q3 2026 — JIRA-1234"

  - check_id: K8S-007
    reason: "Internal registry enforces immutable tags at push time"

  - check_id: K8S-012
    resource: Deployment/batch-worker
    reason: "Batch job — uses job completion as health signal, no HTTP endpoint"
```

See `samples/.k8s-checker-ignore.yaml` for a full annotated example.

## Live cluster analysis

If `kubectl` is configured and connected to a cluster, the agent will automatically
query runtime state alongside the static manifest analysis:

- Running pods and their security contexts
- RBAC bindings (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings)
- NetworkPolicies per namespace
- Secrets (names and types only — values are never read)

No additional setup is required. If `kubectl` is not available or no cluster is connected,
this step is skipped gracefully.

## Helm chart support

Point the agent at a directory containing `Chart.yaml` and it will automatically run
`helm template` to render the manifests before analysis:

```bash
python agent.py ./my-helm-chart/
python agent.py ./my-helm-chart/ --output reports/helm-scan.md
```

Requires [Helm](https://helm.sh/docs/intro/install/) to be installed. Falls back gracefully if not available.

## Optional: CVE scanning with Trivy

If [Trivy](https://aquasecurity.github.io/trivy/) is installed, the agent will scan
container images for known CVEs. Without it, that step is skipped gracefully.

```bash
brew install trivy   # macOS
```

## Running tests

```bash
pytest tests/ -v
```

48 unit tests cover all 14 static checks and the suppression allowlist logic.
All tests run offline — no API key or cluster connection required.

## Static checks covered

| Check ID | Category | Severity |
|----------|----------|----------|
| K8S-001 | Privileged container | CRITICAL |
| K8S-002 | Host namespaces (PID / IPC / Network) | CRITICAL / HIGH |
| K8S-003 | Root user (UID 0 or runAsNonRoot: false) | HIGH / MEDIUM |
| K8S-004 | Dangerous capabilities (SYS_ADMIN, ALL, …) | CRITICAL / HIGH |
| K8S-005 | Writable root filesystem | MEDIUM |
| K8S-006 | Missing resource limits / requests | MEDIUM / LOW |
| K8S-007 | Unpinned image tag (:latest or no tag) | MEDIUM |
| K8S-008 | Service account token auto-mount | MEDIUM |
| K8S-009 | hostPath volumes | CRITICAL / HIGH |
| K8S-010 | Missing labels (NetworkPolicy targeting) | LOW |
| K8S-011 | Hardcoded secrets in env vars | HIGH |
| K8S-012 | Missing liveness / readiness probes | LOW |
| K8S-013 | Missing pod-level securityContext / seccomp | MEDIUM |
| K8S-014 | RBAC wildcard verbs or resources | CRITICAL / HIGH |

## Project structure

```
kubesentinel/
├── agent.py            # Entry point — CLI arg parsing, orchestration
├── analyzer.py         # YAML parser, static checks, CHECK_REGISTRY
├── claude_agent.py     # Agentic loop using Anthropic tool_use API
├── tools.py            # Tool schemas (JSON) + execution functions
├── reporter.py         # Markdown report renderer
├── suppressor.py       # Suppression allowlist loader and filter
├── requirements.txt
├── .env.example        # API key template — copy to .env
├── CONTRIBUTING.md     # Guide for adding checks, tools, and tests
├── tests/
│   ├── test_analyzer.py    # 40 unit tests for static checks
│   └── test_suppressor.py  # 8 unit tests for suppression logic
├── samples/
│   ├── vulnerable.yaml              # Intentionally broken manifest — for testing
│   ├── secure.yaml                  # Hardened example
│   └── .k8s-checker-ignore.yaml    # Example suppression config
└── reports/                         # Output directory (gitignored)
```

## CI/CD integration

```yaml
# GitHub Actions example
- name: K8s security check
  run: |
    python -m pip install -r requirements.txt
    python agent.py k8s/ --output reports/security.md
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Exit codes: `0` = clean, `1` = error, `2` = CRITICAL findings detected.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new static checks, new agent tools,
run the test suite, and submit pull requests.

## Extending

**Add a static check:** implement a function in `analyzer.py` that takes `(resource, context)`
and returns a finding dict or `None`, then register it in `CHECK_REGISTRY` and add tests.

**Add a tool:** define its JSON schema in the `TOOLS` list in `tools.py`, add an execution
function, and wire it into the `execute_tool` dispatcher. Claude will start calling it
automatically.

**Tune the agent's focus:** adjust `SYSTEM_PROMPT` in `claude_agent.py` to bias Claude
toward specific workload types — 5G core NFs, CNF sidecars, service mesh, DPDK, etc.

## Troubleshooting

**`ModuleNotFoundError: No module named 'dotenv'` (or any other module)**

This means `pip` installed the package into the system Python instead of your venv.
Always use `python -m pip` after activating the venv:

```bash
source venv/bin/activate
python -m pip install -r requirements.txt

# Verify the right Python is active
which python        # should point inside your venv/bin/
python -m pip list  # should show anthropic, pyyaml, etc.
```

**`ANTHROPIC_API_KEY not set`**

Either export it in your shell or add it to a `.env` file in the project root:

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
# or
echo "ANTHROPIC_API_KEY=sk-ant-your-key-here" > .env
```

**Trivy / helm / kubectl not found**

These are optional. The agent skips each step gracefully if the tool isn't installed.
Install only what you need:

```bash
brew install trivy    # CVE scanning
brew install helm     # Helm chart rendering
# kubectl — install via your cloud provider CLI or https://kubernetes.io/docs/tasks/tools/
```
