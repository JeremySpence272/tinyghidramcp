"""Build-time metadata.

A build hook may overwrite this file at wheel-build time to bake in the source
git SHA. At runtime we prefer this value; if it's None, we fall back to a
subprocess ``git rev-parse HEAD`` from the package install directory (works in
dev installs); if that also fails, we report ``None`` and move on.
"""

GIT_SHA: str | None = None
