"""Pure helpers for the CVE triage swarm (no SDK imports, unit-testable)."""
from __future__ import annotations

import re
from typing import TypeVar

T = TypeVar("T")

# Anything that must never appear in a generated PoC: network access,
# subprocesses, dynamic code execution, or file I/O. The PoC runs inside the
# worker container against an in-memory DB only.
FORBIDDEN_POC = re.compile(
    r"(import\s+(socket|urllib|requests|httpx|aiohttp)\b"
    r"|from\s+(socket|urllib|requests|httpx|aiohttp)\b"
    r"|subprocess|os\.system|\bpopen\b|\bexec\s*\(|\beval\s*\(|__import__|\bcompile\s*\("
    r"|\bopen\s*\(|urlopen|\.connect\s*\()",
    re.IGNORECASE,
)


def poc_safe(code: str) -> bool:
    """True if the generated PoC passes the safety filter."""
    return not FORBIDDEN_POC.search(code)


def extract_python(text: str) -> str:
    """Pull the first ```python fenced block out of an LLM answer (else raw text)."""
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


def extract_diff(text: str) -> str:
    """Pull the unified diff out of an LLM answer."""
    m = re.search(r"```(?:diff)?\s*\n(.*?)```", text, re.DOTALL)
    body = m.group(1) if m else text
    body = body.strip()
    # keep from the first diff header onward if there is prose before it
    idx = body.find("--- ")
    if idx > 0:
        body = body[idx:]
    return body


def chunk_strided(items: list[T], n: int) -> list[list[T]]:
    """Split items into n shards, strided so each shard spans the whole tree."""
    if not items:
        return []
    n = max(1, min(n, len(items)))
    return [items[i::n] for i in range(n)]


def verdict_vulnerable(output: str) -> bool:
    """The PoC prints `VERDICT: VULNERABLE` only on a behavioural hit."""
    return "VERDICT: VULNERABLE" in output
