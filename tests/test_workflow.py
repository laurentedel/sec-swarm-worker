"""Unit tests for the pure helpers (no mistralai-workflows install needed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sec_swarm.textutil import (  # noqa: E402
    chunk_strided,
    extract_diff,
    extract_python,
    poc_safe,
    verdict_vulnerable,
)


def test_chunk_strided_covers_all_once():
    items = list(range(20))
    shards = chunk_strided(items, 6)
    assert len(shards) == 6
    flat = sorted(x for s in shards for x in s)
    assert flat == items


def test_chunk_strided_edge_cases():
    assert chunk_strided([], 4) == []
    assert chunk_strided([1, 2], 10) == [[1], [2]]


def test_extract_python():
    text = 'here you go:\n```python\nprint("hi")\n```\ndone'
    assert extract_python(text) == 'print("hi")'
    assert extract_python("print('raw')") == "print('raw')"


def test_extract_diff():
    text = 'prose\n```diff\n--- a/f.py\n+++ b/f.py\n-old\n+new\n```\n'
    d = extract_diff(text)
    assert d.startswith("--- a/f.py")
    assert "+new" in d


def test_poc_safe_blocks_dangerous():
    for bad in [
        "import socket",
        "from urllib.request import urlopen",
        "import subprocess",
        "os.system('id')",
        "eval('1+1')",
        "exec(code)",
        "open('/etc/passwd')",
        "__import__('os')",
    ]:
        assert not poc_safe(bad), bad


def test_poc_safe_allows_django_poc():
    good = (
        "import os, sys\n"
        "from django.db import connection\n"
        "with connection.cursor() as c:\n"
        "    c.execute('SELECT 1')\n"
    )
    assert poc_safe(good)


def test_verdict():
    assert verdict_vulnerable("... VERDICT: VULNERABLE\n")
    assert not verdict_vulnerable("... VERDICT: BLOCKED\n")
