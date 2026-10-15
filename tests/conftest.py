from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from antiphish.kb import SCHEMA


@pytest.fixture
def empty_kb(tmp_path):
    path = tmp_path / "knowledge.sqlite"
    with closing(sqlite3.connect(path)) as con:
        con.executescript(SCHEMA)
    return path
