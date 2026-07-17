from __future__ import annotations

import os
from typing import IO


if os.name == "nt":
    import msvcrt
else:
    import fcntl


def try_lock(handle: IO[str], *, exclusive: bool = True) -> bool:
    """Try to acquire a non-blocking one-byte process lock."""
    if os.name == "nt":
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write("\0")
            handle.flush()
        handle.seek(0)
        try:
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
