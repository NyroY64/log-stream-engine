import pytest


@pytest.fixture
def rec():
    """Build a minimal normalised record."""

    def build(ip, kind, level="ERROR"):
        return {
            "src_ip": ip,
            "kind": kind,
            "level": level,
            "user_id": None,
            "meta": None,
            "line": "",
        }

    return build
