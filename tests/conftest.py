import os
from pathlib import Path

import pytest

from app.server import create_app
from app.storage import JsonStorage


@pytest.fixture
def temp_storage(tmp_path: Path):
    users_path = tmp_path / "users.json"
    messages_path = tmp_path / "messages.json"
    storage = JsonStorage(users_path=users_path, messages_path=messages_path)
    return storage


@pytest.fixture
def app(temp_storage):
    flask_app = create_app(storage=temp_storage)
    flask_app.config.update({"TESTING": True})
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()
