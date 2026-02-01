import os
import sqlite3
import tempfile
from collections.abc import Generator

import pytest

from ntrip_caster import config
from ntrip_caster.database import init_db


@pytest.fixture
def temp_db() -> Generator[str, None, None]:
    """Fixture for a temporary database"""
    fd, path = tempfile.mkstemp()
    original_db_path = config.settings.database.path
    config.settings.database.path = path

    # Initialize the database
    init_db()

    yield path

    # Cleanup
    os.close(fd)
    if os.path.exists(path):
        os.remove(path)
    config.settings.database.path = original_db_path


@pytest.fixture
def db_conn(temp_db: str) -> Generator[sqlite3.Connection, None, None]:
    """Fixture for a database connection"""
    conn = sqlite3.connect(temp_db)
    yield conn
    conn.close()
