"""Read-only SQLite URIs that survive any file name.

A hand-built ``file:{path}?mode=ro`` treats ``#`` as the start of a fragment and decodes ``%41`` as a letter, so a file
called ``notes#1.db`` or ``100%41.db`` silently opens a different (missing) file. ``Path.as_uri()`` percent-encodes them.
"""
from __future__ import annotations

import os
import pathlib
from typing import Union


def ro_uri(path: Union[str, "os.PathLike[str]"], extra: str = "") -> str:
    """``file:`` URI for ``path`` opened with ``mode=ro`` (plus any extra query such as ``&immutable=1``)."""
    return pathlib.Path(os.path.abspath(os.fspath(path))).as_uri() + "?mode=ro" + extra
