import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str):
        path = FIXTURES / name
        return json.loads(path.read_text(encoding="utf-8")) if path.suffix == ".json" else path

    return _load
