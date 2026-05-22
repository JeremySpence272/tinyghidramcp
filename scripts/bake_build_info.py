#!/usr/bin/env python3
"""Bake the current git SHA into ``tinyghidramcp/_build_info.py``.

Run this once before ``pip install`` / ``pip wheel`` if you want telemetry's
``session_start.tinyghidramcp_git_sha`` to be populated. Without this step, the
runtime falls back to ``git rev-parse HEAD`` -- which works in dev installs
but fails in revbench's stripped production container.

Usage:
    python scripts/bake_build_info.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_INFO = REPO_ROOT / "tinyghidramcp" / "_build_info.py"


def main() -> int:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"bake_build_info: could not read git SHA ({exc})")
        return 1

    sha = out.stdout.strip()
    BUILD_INFO.write_text(
        '"""Build-time metadata (baked by scripts/bake_build_info.py)."""\n'
        f'\nGIT_SHA: str | None = "{sha}"\n'
    )
    print(f"baked GIT_SHA = {sha} -> {BUILD_INFO.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
