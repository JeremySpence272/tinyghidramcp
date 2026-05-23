"""faulthandler is installed on server start; SIGUSR1 dumps thread stacks."""

from __future__ import annotations

import faulthandler
import signal
import sys


def test_faulthandler_installer_does_not_raise():
    """The installer should be safe to call repeatedly without error."""
    from tinyghidramcp.cli import _install_faulthandler

    _install_faulthandler()
    assert faulthandler.is_enabled()


def test_sigusr1_is_registered_after_install():
    """After _install_faulthandler, SIGUSR1 should be registered with faulthandler."""
    from tinyghidramcp.cli import _install_faulthandler

    _install_faulthandler()
    sig = getattr(signal, "SIGUSR1", None)
    if sig is None:
        # Platform doesn't support SIGUSR1 (Windows); installer should still be safe.
        return
    # faulthandler.unregister returns True if the signal was registered;
    # we re-register immediately so we don't break other tests.
    was_registered = faulthandler.unregister(sig)
    if was_registered:
        faulthandler.register(sig, file=sys.stderr, all_threads=True)
    assert was_registered, "SIGUSR1 should be registered by _install_faulthandler"
