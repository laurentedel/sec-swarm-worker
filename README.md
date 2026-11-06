# sec-swarm-worker

A multi-agent **"find / prove / patch a CVE"** swarm, deployed as a managed
[Mistral Studio Workflow](https://docs.mistral.ai/studio/workflows/) — the
observable, Temporal-backed counterpart of the "133 agents" demo
(x.com/MistralAI/status/2117925908572991748).

Default target: **Django @ 5.2.10**, CVE-2026-1312 (GHSA-6426-9fv3-65x8) — SQL
injection via `QuerySet.order_by()` when a dotted alias is also used as a
`FilteredRelation` (dict expansion).

## Pipeline

```
clone ─▶ map-code (file list + sink grep)
      ─▶ shard-scan   fan-out: N parallel recon activities over file shards
      ─▶ hunt         LLM synthesises findings -> root cause (JSON)
      ─▶ poc          LLM writes a PoC; the worker RUNS it (sandboxed:
                       in-memory SQLite only, network/subprocess/eval filtered,
                       120 s timeout)
      ─▶ patch        LLM produces a minimal unified diff
      ─▶ verify       apply patch to a copy of the tree, re-run the PoC
      ─▶ report       LLM writes the final markdown report
```

Every stage emits a `task` progress event; executions, per-stage events and
logs are inspectable in Mistral Studio. LLM calls go through the official
plugin activity `mistralai_chat_complete`; on a managed deployment the
service-account token is injected by the platform (no API key in the image).

## Layout

- `sec_swarm/workflow.py` — `cve-triage-swarm` workflow + activities
- `sec_swarm/textutil.py` — pure helpers (chunking, LLM-output extraction, PoC safety filter)
- `worker.py` — `run_worker([CveTriageSwarm])`
- `Dockerfile` — worker image (python:3.12-slim + git + patch)
- `tests/test_workflow.py` — unit tests for the pure helpers (`python3 -m pytest tests/` or plain `python3 tests/test_workflow.py`-style asserts)

## Deploy (managed)

The repo must be readable by the Mistral GitHub App (github.com/apps/mistralai).
Then, via the Studio API / MCP:

```python
deploy_workflow_deployment(
    deployment_name="sec-swarm-worker",
    github_url="https://github.com/laurentedel/sec-swarm-worker",
    revision="<pushed commit SHA>",
    build_directory=".",
    dockerfile_path="Dockerfile",
)
wait_workflow_deployment_ready(deployment_name="sec-swarm-worker",
                               expected_revision="<SHA>", timeout_s=900)
```

## Run

```python
execute_workflow(
    workflow_identifier="cve-triage-swarm",
    deployment_name="sec-swarm-worker",
    input={
        "repo_url": "https://github.com/django/django.git",
        "ref": "5.2.10",
        "cve_hint": "SQLi in QuerySet.order_by() via FilteredRelation dotted alias (CVE-2026-1312)",
        "model": "mistral-large-latest",
        "fanout": 6,
        "run_poc": True,
    },
)
```

Output (`SwarmOutput`) carries the full audit trail: sink hits, per-shard
reports, hunter findings, the PoC source, its output before/after the patch,
the patch diff, and the final markdown report. `ok=True` means the exploit was
proven on the vulnerable tree and killed on the patched copy.

## Safety

PoC execution is demo-grade only: regex safety filter (no network, subprocess,
eval/exec, file I/O), 120 s subprocess timeout, in-memory database, executed
against the freshly cloned local tree — never against real systems.
