"""Build-info: prefer baked GIT_SHA, fall back to subprocess, then None."""

from __future__ import annotations

from unittest.mock import patch

from tinyghidramcp.cli import _git_sha_at_runtime


def test_baked_sha_is_preferred():
    with patch("tinyghidramcp._build_info.GIT_SHA", "deadbeefcafef00d"):
        assert _git_sha_at_runtime() == "deadbeefcafef00d"


def test_subprocess_fallback_when_unbaked():
    """In a dev checkout we expect git rev-parse to work."""
    with patch("tinyghidramcp._build_info.GIT_SHA", None):
        sha = _git_sha_at_runtime()
        # Either a real SHA (40 hex chars) or None if git isn't on PATH.
        if sha is not None:
            assert len(sha) == 40
            int(sha, 16)  # hex


def test_returns_none_when_git_unavailable_and_unbaked():
    with patch("tinyghidramcp._build_info.GIT_SHA", None), \
         patch("subprocess.run", side_effect=FileNotFoundError):
        assert _git_sha_at_runtime() is None
