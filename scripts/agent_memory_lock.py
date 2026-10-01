from __future__ import annotations

import os
import contextlib
import stat
import time
from pathlib import Path
from typing import IO

from agent_memory_state import (
    POSIX_PERMISSION_MODEL,
    PRIVATE_FILE_MODE,
    StateSecurityError,
    ensure_private_directory,
)


if os.name == "nt":
    import msvcrt
else:
    import fcntl


def try_lock(handle: IO[str], *, exclusive: bool = True) -> bool:
    """Try to acquire a non-blocking process lock."""

    if os.name == "nt":
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write("\0")
            handle.flush()
        handle.seek(0)
        try:
            # msvcrt has no shared-lock primitive.  Serializing all callers is
            # the safe match for Zvec, which opens collections read-write.
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(handle.fileno(), operation | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def unlock(handle: IO[str]) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def private_lock(path: Path, *, timeout: float, timeout_message: str):
    """Open one private non-symlink lock file and acquire it with a deadline."""

    ensure_private_directory(path.parent, harden_existing=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StateSecurityError(f"private lock is not a regular file: {path}")
        if POSIX_PERMISSION_MODEL:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
            descriptor = -1
            deadline = time.monotonic() + max(timeout, 0.0)
            while not try_lock(handle):
                if time.monotonic() >= deadline:
                    raise TimeoutError(timeout_message)
                time.sleep(0.1)
            try:
                yield
            finally:
                unlock(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
