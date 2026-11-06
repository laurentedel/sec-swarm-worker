"""cve-triage-swarm — a multi-agent "find / prove / patch a CVE" pipeline as a
Mistral Studio Workflow (managed, observable, parallel).

Stages (each emits a `task` progress event visible in Studio):

    clone ─▶ map-code (list files + grep dangerous sinks)
          ─▶ shard-scan (fan-out: N parallel recon activities over file shards)
          ─▶ hunt        (LLM synthesises the findings into a root-cause report)
          ─▶ poc         (LLM writes a PoC; the worker RUNS it, sandboxed,
                          in-memory DB only, network/subprocess/eval filtered)
          ─▶ patch       (LLM produces a unified diff)
          ─▶ verify      (apply patch to a copy, re-run the PoC)
          ─▶ report      (LLM writes the final markdown report)

All LLM calls (`mistralai_chat_complete` from the official plugin) happen in
the workflow entrypoint; all I/O happens in activities, per the SDK rules.
On a managed deployment the platform injects the service-account token, so no
API key is needed in the image.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from pydantic import BaseModel, Field

from mistralai.workflows import activity, execute_activities_in_parallel, task, workflow
from mistralai.workflows.plugins.mistralai import (
    ChatCompletionRequest,
    UserMessage,
    mistralai_chat_complete,
)

from .textutil import (
    chunk_strided,
    extract_diff,
    extract_python,
    poc_safe,
    verdict_vulnerable,
)

# ---------------------------------------------------------------------------
# Input / output models
# ---------------------------------------------------------------------------


class SwarmInput(BaseModel):
    repo_url: str = "https://github.com/django/django.git"
    ref: str = "5.2.10"
    cve_hint: str = (
        "SQL injection in QuerySet.order_by() when a dotted alias is also used "
        "via dict expansion as FilteredRelation (CVE-2026-1312, GHSA-6426-9fv3-65x8)"
    )
    model: str = "mistral-large-latest"
    fanout: int = 6
    run_poc: bool = True


class ShardReport(BaseModel):
    shard_id: int
    files: int
    candidates: list[str] = Field(default_factory=list)


class SwarmOutput(BaseModel):
    ok: bool
    target: str
    files_scanned: int
    sink_hits: dict[str, list[str]]
    shard_reports: list[ShardReport]
    findings: str
    poc_code: str
    poc_before: str
    poc_after: str
    patch_diff: str
    patch_applied: bool
    report: str


# ---------------------------------------------------------------------------
# Activities — every side effect lives here
# ---------------------------------------------------------------------------

ACT10 = dict(start_to_close_timeout=timedelta(minutes=10), retry_policy_max_attempts=2)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run that returns rc=127 instead of raising if the binary is missing."""
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, 127, stderr=f"binary missing: {exc}")

SINK_PATTERNS: dict[str, str] = {
    "order_by": r"\.order_by\(",
    "filtered_relation": r"FilteredRelation",
    "raw_sql": r"RawSQL\(",
    "extra_order_by": r"extra_order_by",
    "raw_query": r"\.raw\(|RawQuery|connection\.cursor",
    "extra_kwarg": r"\.extra\(",
    "add_filtered_relation": r"add_filtered_relation",
    "names_to_path": r"def names_to_path",
}


@activity(start_to_close_timeout=timedelta(minutes=15), retry_policy_max_attempts=2)
async def clone_repo(repo_url: str, ref: str, workdir: str) -> str:
    """Shallow-clone the target repo at `ref` into workdir/target."""
    dest = Path(workdir) / "target"
    if dest.exists():
        shutil.rmtree(dest)
    Path(workdir).mkdir(parents=True, exist_ok=True)
    r = _run(
        ["git", "clone", "--depth", "1", "--branch", ref, repo_url, str(dest)],
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:  # ref may be a commit sha, not a tag: clone then checkout
        r2 = _run(
            ["git", "clone", "--depth", "1", repo_url, str(dest)],
            capture_output=True, text=True, timeout=600,
        )
        if r2.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr[-400:]} / {r2.stderr[-400:]}")
        _run(["git", "-C", str(dest), "checkout", ref],
             capture_output=True, text=True, timeout=300)
    if not dest.exists():
        raise RuntimeError("clone produced no directory")
    return str(dest)


@activity(**ACT10)
async def list_source_files(target: str, max_files: int = 3000) -> list[str]:
    root = Path(target) / "django"
    if not root.is_dir():
        root = Path(target)
    files = sorted(
        str(p.relative_to(target))
        for p in root.rglob("*.py")
        if "__pycache__" not in str(p)
    )
    return files[:max_files]


@activity(**ACT10)
async def grep_sinks(target: str, max_per_pattern: int = 60) -> dict[str, list[str]]:
    root = Path(target)
    out: dict[str, list[str]] = {}
    for name, pat in SINK_PATTERNS.items():
        rx = re.compile(pat)
        hits: list[str] = []
        for p in sorted(root.rglob("*.py")):
            if "__pycache__" in str(p):
                continue
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{p.relative_to(root)}:{i}: {line.strip()[:160]}")
                    if len(hits) >= max_per_pattern:
                        break
            if len(hits) >= max_per_pattern:
                break
        out[name] = hits
    return out


@activity(**ACT10)
async def scan_shard(target: str, shard_id: int, files: list[str], cve_hint: str) -> ShardReport:
    """Deterministic per-shard recon: flag files touching the dangerous APIs."""
    root = Path(target)
    kw = re.compile(
        r"(order_by|FilteredRelation|RawSQL|extra_order_by|_filtered_relations|"
        r"add_filtered_relation|names_to_path)",
        re.IGNORECASE,
    )
    candidates: list[str] = []
    for rel in files:
        p = root / rel
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if kw.search(line):
                candidates.append(f"{rel}:{i}: {line.strip()[:160]}")
                if len(candidates) >= 40:
                    break
        if len(candidates) >= 40:
            break
    return ShardReport(shard_id=shard_id, files=len(files), candidates=candidates[:40])


@activity(**ACT10)
async def read_source(target: str, rel: str, max_chars: int = 6000) -> str:
    p = Path(target) / rel
    try:
        text = p.read_text(errors="ignore")
    except OSError as exc:
        return f"# unreadable: {exc}"
    return f"# {rel}\n{text[:max_chars]}"


@activity(**ACT10)
async def read_source_window(target: str, rel: str, line: int, before: int = 70, after: int = 70) -> str:
    """Read a numbered window of lines around `line` (for exact patch context)."""
    p = Path(target) / rel
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError as exc:
        return f"# unreadable: {exc}"
    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    body = "\n".join(f"{i}: {lines[i - 1]}" for i in range(lo, hi + 1))
    return f"# {rel} lines {lo}-{hi}\n{body}"


@activity(**ACT10)
async def find_line(target: str, needle: str) -> dict:
    """Locate the first file:line containing `needle` (deterministic sink locator)."""
    root = Path(target)
    for p in sorted(root.rglob("*.py")):
        if "__pycache__" in str(p):
            continue
        try:
            for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                if needle in line:
                    return {"file": str(p.relative_to(root)), "line": i, "text": line.strip()[:160]}
        except OSError:
            continue
    return {"file": "", "line": 0, "text": ""}


@activity(start_to_close_timeout=timedelta(minutes=5), retry_policy_max_attempts=1)
async def run_poc(target: str, poc_code: str, tag: str) -> dict:
    """Write the generated PoC to disk and execute it against the local tree.

    Safety: the code is regex-filtered (no network/subprocess/eval/file IO),
    run with a 120s timeout, cwd outside the repo, PYTHONPATH pointed at the
    target tree, in-memory DB only. Never touches real systems.
    """
    if not poc_safe(poc_code):
        return {"tag": tag, "ok": False, "returncode": -1,
                "output": "PoC rejected by safety filter (network/subprocess/eval/file-IO)"}
    work = Path(target).parent
    poc_path = work / f"_poc_{tag}.py"
    poc_path.write_text(poc_code)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(target).resolve()) + os.pathsep + env.get("PYTHONPATH", "")
    env["DJANGO_VENDOR"] = str(Path(target).resolve())
    try:
        r = subprocess.run(
            [sys.executable, str(poc_path)],
            capture_output=True, text=True, timeout=120, cwd=str(work), env=env,
        )
        out = (r.stdout + r.stderr)[-4000:]
        return {"tag": tag, "ok": r.returncode == 0, "returncode": r.returncode, "output": out}
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout if isinstance(exc.stdout, str) else ""
        return {"tag": tag, "ok": False, "returncode": -1,
                "output": f"TIMEOUT after 120s\n{partial[-1000:]}"}


@activity(start_to_close_timeout=timedelta(minutes=10), retry_policy_max_attempts=1)
async def apply_patch(target: str, patch_diff: str) -> dict:
    """Apply the LLM patch to a COPY of the tree (original stays intact)."""
    src = Path(target)
    dst = src.parent / "target_patched"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    patch_file = src.parent / "_fix.patch"
    patch_file.write_text(patch_diff)
    r = _run(["git", "apply", "--whitespace=fix", str(patch_file)],
             cwd=str(dst), capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        return {"applied": True, "patched_path": str(dst), "method": "git apply", "err": ""}
    r2 = _run(["patch", "-p1", "-f", "-i", str(patch_file)],
              cwd=str(dst), capture_output=True, text=True, timeout=120)
    if r2.returncode == 0:
        return {"applied": True, "patched_path": str(dst), "method": "patch -p1", "err": ""}
    return {"applied": False, "patched_path": "",
            "method": "", "err": (r.stderr + r2.stderr)[-600:]}


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

HUNT_PROMPT = """You are the HUNTER agent in a security swarm auditing a source tree for a known CVE.

CVE hint: {cve_hint}

Sink grep results (pattern -> file:line hits):
{sinks}

Parallel shard-scan candidates (file:line hits from {n_shards} recon agents):
{candidates}

Source snippets of the most suspicious files:
{snippets}

Task: pinpoint the vulnerability. Answer with ONLY a JSON object:
{{
  "root_cause": "one paragraph",
  "sink": "file:line of the dangerous line",
  "vulnerable_files": ["..."],
  "entry_point": "public API a caller reaches this through",
  "exploit_primitive": "what an attacker controls and what it reaches",
  "suggested_fix": "one or two sentences"
}}
"""

POC_PROMPT = """You are the POC agent in a security swarm. Write a MINIMAL, self-contained Python
exploit that PROVES the vulnerability behaviourally, against the local source tree only.

Findings from the hunter:
{findings}

Relevant code:
{snippets}

Hard constraints:
- Single Python file, stdlib + the target package only (Django is already importable:
  PYTHONPATH points at the cloned tree and DJANGO_VENDOR is set).
- Configure Django yourself, exactly along these lines:
    settings.configure(
        DEBUG=True,  # enables connection.queries logging
        DATABASES={{"default": {{"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}}},
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
        USE_TZ=True,
    )
    django.setup()
  Then define models with an explicit `app_label = "poc"` in Meta and create tables with
  `with connection.schema_editor() as se: se.create_model(...)`.
  Do NOT put "poc" in INSTALLED_APPS — no such module exists and django.setup() will crash.
- NO network, NO subprocess, NO eval/exec, NO file I/O. In-memory DB only. Never touch
  real systems.
- Runtime must stay under 60 seconds.

The exploit pattern to reproduce (this is the CVE): a DOTTED string alias is used BOTH as
a dict-expansion key for FilteredRelation AND as the order_by() argument. In the
vulnerable compiler, everything after the FIRST "." of such an alias is emitted RAW into
ORDER BY. Skeleton (see also tests/annotations/tests.py for the crafted_alias pattern):

    crafted = "<model_table>.id*0+" + payload   # one SQL expression, NO commas/quotes;
                                                # use char(N) instead of string literals
    qs = (Model.objects
          .extra(tables=["vault"])                          # bring an out-of-scope table into scope
          .annotate(**{{crafted: FilteredRelation("author")}})  # dotted alias as dict key
          .order_by(crafted))                               # same alias in order_by

Define two models with a ForeignKey (e.g. Author -> Article, relation name "author"),
create a "vault" table with a secret via connection.cursor(), then prove the injection
BEHAVIOURALLY: run the query with two different boolean guesses (e.g. substr(vault.secret,1,1)=char(N))
and check whether the ROW ORDER flips (boolean-blind oracle), and/or print the compiled
ORDER BY from str(qs.query). Base the verdict on that behaviour, not on the version string.

- End stdout with exactly one verdict line: "VERDICT: VULNERABLE" if the injection
  demonstrably executed (row order flipped or injected SQL present in the EXECUTED
  statement via connection.queries), otherwise "VERDICT: BLOCKED".

Return ONLY the code in a single ```python fenced block.
"""

POC_REPAIR_PROMPT = """You are the POC agent in a security swarm. The previous PoC ran but did NOT
print the required verdict (it crashed or the exploit never fired). Fix it and keep the
same verdict contract.

Previous code:
```python
{code}
```

Output it produced (tail):
{err}

Checklist:
- INSTALLED_APPS must be ["django.contrib.contenttypes", "django.contrib.auth"] (never "poc").
- The crafted alias MUST be a DOTTED string used both as annotate(**{{alias: FilteredRelation(...)}})
  key and as order_by(alias) argument — a plain non-dotted string will NOT reach the raw
  ORDER BY passthrough.
- The FilteredRelation relation_name must be a REAL relation of the model (e.g. the FK "author").
- payload must be a single SQL expression without commas or quotes (use char(N)); prefix
  with "<table>.id*0+" so it stays one expression.
- Use .extra(tables=["vault"]) to bring the secret table into scope, create it with
  connection.cursor(), and read the executed SQL from connection.queries (needs DEBUG=True).
- Compare row order for two guesses to detect the boolean-blind oracle flip.

Return ONLY the fixed code in a single ```python fenced block.
"""

PATCH_PROMPT = """You are the PATCHER agent in a security swarm. Produce a MINIMAL fix for the root
cause, as a unified diff that applies CLEANLY with `git apply` from the repository root
(paths like a/django/db/... and b/django/db/...).

Findings:
{findings}

Relevant code (numbered, exact lines — copy context EXACTLY, indentation included):
{snippets}

Rules:
- The sink is the `if "." in field:` branch inside SQLCompiler._order_by_pairs in
  django/db/models/sql/compiler.py — the numbered snippet below shows it verbatim.
  Fix THAT branch; do not refactor anything else.
- Minimal upstream-style fix: only take the raw passthrough when the dotted field is
  explicitly whitelisted, i.e. the condition should also require the field to be present
  in self.query.extra_order_by (check how extra_order_by is populated); otherwise fall
  through to normal field resolution.
- Keep hunks small; copy the surrounding context lines verbatim from the snippet and
  keep the @@ line counts correct, or `git apply` will reject the diff.
- Do not invent code that is not in the snippet.

Return ONLY the diff in a single ```diff fenced block.
"""

PATCH_REPAIR_PROMPT = """You are the PATCHER agent. `git apply` REJECTED the previous diff:

Error:
{err}

Previous diff:
```diff
{diff}
```

Exact current source (numbered lines):
{snippets}

Rewrite the diff so it applies cleanly: copy context lines verbatim from the source
above, fix the @@ hunk headers, keep paths a/... and b/.... Return ONLY the new diff in
a single ```diff fenced block.
"""

REPORT_PROMPT = """You are the RAPPORTEUR agent in a security swarm. Write the final markdown report of
the whole triage (this is shown to engineers in Mistral Studio).

Input: repo={repo} ref={ref}
CVE hint: {cve_hint}
Files scanned: {n_files}, shards: {n_shards}
Hunter findings:
{findings}
PoC (before patch) verdict/output:
{poc_before}
Patch applied: {patch_applied}
PoC (after patch) verdict/output:
{poc_after}
Patch:
{patch_diff}

Sections: Target, Method, Findings, PoC, Patch, Verification, Conclusion.
Base every claim on the ACTUAL outputs: the exploit is "proven" ONLY if the before-patch
output contains "VERDICT: VULNERABLE"; if the PoC crashed without a verdict line, say so
explicitly. The patch is "verified" ONLY if the after-patch output lacks that verdict.
"""

# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------


@workflow.define(name="cve-triage-swarm", execution_timeout=timedelta(minutes=60))
class CveTriageSwarm:
    @workflow.entrypoint
    async def run(self, params: SwarmInput) -> SwarmOutput:
        run_id = workflow.uuid4()
        workdir = f"/tmp/sec-swarm-{run_id}"

        # 1. clone ------------------------------------------------------------
        async with task("clone-repo", {"repo": params.repo_url, "ref": params.ref}):
            target = await clone_repo(params.repo_url, params.ref, workdir)

        # 2. map the code ------------------------------------------------------
        async with task("map-code", {"step": "list files + grep sinks"}):
            files = await list_source_files(target)
            sinks = await grep_sinks(target)

        # 3. parallel shard scan (the "swarm") ---------------------------------
        shards = chunk_strided(files, params.fanout)
        items = [
            {"target": target, "shard_id": i, "files": chunk, "cve_hint": params.cve_hint}
            for i, chunk in enumerate(shards)
            if chunk
        ]
        async with task("shard-scan", {"shards": len(items), "files": len(files)}) as t:
            shard_reports = await execute_activities_in_parallel(scan_shard, items=items)
            await t.update_state({"candidates": sum(len(r.candidates) for r in shard_reports)})

        # gather the most suspicious files as snippets for the LLM stages
        cand_files: list[str] = []
        for rep in shard_reports:
            for cand in rep.candidates:
                f = cand.split(":", 1)[0]
                if f not in cand_files:
                    cand_files.append(f)
            if len(cand_files) >= 8:
                break
        snippet_parts = []
        for f in cand_files[:8]:
            snippet_parts.append(await read_source(target, f))
        snippets = "\n\n".join(snippet_parts)

        sinks_txt = json.dumps(sinks, indent=1)[:6000]
        cands_txt = "\n".join(
            c for rep in shard_reports for c in rep.candidates
        )[:6000]

        # 4. hunt (LLM) ---------------------------------------------------------
        async with task("hunt", {"model": params.model}):
            findings = await self._llm(
                params.model,
                HUNT_PROMPT.format(
                    cve_hint=params.cve_hint, sinks=sinks_txt,
                    n_shards=len(shards), candidates=cands_txt, snippets=snippets[:8000],
                ),
            )

        # deterministic sink locator -> exact numbered context for the poc/patch prompts
        loc = await find_line(target, 'if "." in field:')
        focus = ""
        if loc["file"]:
            focus = await read_source_window(target, loc["file"], loc["line"])
        poc_snippets = ((focus + "\n\n" + snippets) if focus else snippets)[:9000]

        # 5. PoC: generate (LLM) then run (activity), with one repair round if it crashes
        async with task("poc-generate", {"model": params.model}):
            poc_code = extract_python(
                await self._llm(
                    params.model,
                    POC_PROMPT.format(findings=findings[:4000], snippets=poc_snippets),
                )
            )
        poc_before = {"tag": "before", "ok": False, "returncode": -1, "output": "skipped (run_poc=false)"}
        if params.run_poc:
            async with task("poc-run", {"sandbox": "in-memory DB, filtered, 120s timeout"}):
                poc_before = await run_poc(target, poc_code, "before")
            for attempt in range(1, 3):  # up to 2 repair rounds if no verdict line
                if "VERDICT:" in poc_before.get("output", ""):
                    break
                async with task("poc-repair", {"attempt": attempt, "reason": "no verdict line"}):
                    poc_code = extract_python(
                        await self._llm(
                            params.model,
                            POC_REPAIR_PROMPT.format(
                                code=poc_code[:4000], err=poc_before.get("output", "")[-1500:]),
                        )
                    )
                    poc_before = await run_poc(target, poc_code, "before")

        # 6. patch (LLM), with one repair round if git apply rejects the diff ---------
        async with task("patch-generate", {"model": params.model}):
            patch_diff = extract_diff(
                await self._llm(
                    params.model,
                    PATCH_PROMPT.format(findings=findings[:4000], snippets=poc_snippets),
                )
            )

        # 7. verify: apply to a copy (up to 2 repair rounds), re-run the PoC --------
        async with task("apply-patch", {}):
            applied = await apply_patch(target, patch_diff)
        for attempt in range(1, 3):
            if applied["applied"]:
                break
            async with task("patch-repair", {"attempt": attempt, "err": applied["err"][-150:]}):
                patch_diff = extract_diff(
                    await self._llm(
                        params.model,
                        PATCH_REPAIR_PROMPT.format(
                            diff=patch_diff[:3000], err=applied["err"][-800:],
                            snippets=poc_snippets[:6000]),
                    )
                )
                applied = await apply_patch(target, patch_diff)
        poc_after = {"tag": "after", "ok": False, "returncode": -1, "output": "not run"}
        if params.run_poc and applied["applied"]:
            async with task("poc-verify", {"tree": "patched copy"}):
                poc_after = await run_poc(applied["patched_path"], poc_code, "after")

        ok = (
            verdict_vulnerable(poc_before.get("output", ""))
            and not verdict_vulnerable(poc_after.get("output", ""))
        )

        # 8. report (LLM) -----------------------------------------------------------
        async with task("report", {}):
            report = await self._llm(
                params.model,
                REPORT_PROMPT.format(
                    repo=params.repo_url, ref=params.ref, cve_hint=params.cve_hint,
                    n_files=len(files), n_shards=len(shards), findings=findings[:4000],
                    poc_before=poc_before.get("output", "")[:2000],
                    patch_applied=applied["applied"],
                    poc_after=poc_after.get("output", "")[:2000],
                    patch_diff=patch_diff[:3000],
                ),
            )

        return SwarmOutput(
            ok=ok,
            target=target,
            files_scanned=len(files),
            sink_hits=sinks,
            shard_reports=shard_reports,
            findings=findings,
            poc_code=poc_code,
            poc_before=poc_before.get("output", ""),
            poc_after=poc_after.get("output", ""),
            patch_diff=patch_diff,
            patch_applied=applied["applied"],
            report=report,
        )

    async def _llm(self, model: str, prompt: str) -> str:
        """Single-turn chat completion via the official Mistral plugin activity.

        On a managed deployment the service-account token is injected by the
        platform, so no API key is needed here.
        """
        request = ChatCompletionRequest(model=model, messages=[UserMessage(content=prompt)])
        result = await mistralai_chat_complete(request)
        content = result.choices[0].message.content
        return content if isinstance(content, str) else str(content)
