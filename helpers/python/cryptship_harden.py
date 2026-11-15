"""Re-apply PR_SET_DUMPABLE for a Python app started by cryptship-loader.

The loader marks itself non-dumpable while it holds the content key, but
execve resets that flag, so the app starts dumpable: another process of the
same uid can ptrace it or read /proc/<pid>/mem and /proc/<pid>/exe. Call
set_non_dumpable() as the first thing the app does:

    import cryptship_harden
    cryptship_harden.set_non_dumpable()

This raises the bar against other processes of the same uid; it does not stop
root. Standard library only (ctypes). On non-Linux systems it does nothing and
returns False.
"""

import ctypes
import os
import sys

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


def _prctl(option, arg2=0):
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    rc = prctl(option, arg2, 0, 0, 0)
    if rc < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return rc


def set_non_dumpable():
    """Mark this process non-dumpable. Returns True on Linux, False elsewhere.

    Raises OSError if the prctl call fails on Linux.
    """
    if not sys.platform.startswith("linux"):
        return False
    _prctl(PR_SET_DUMPABLE, 0)
    return True


def is_dumpable():
    """Return the current dumpable flag (always True outside Linux)."""
    if not sys.platform.startswith("linux"):
        return True
    return _prctl(PR_GET_DUMPABLE) != 0
