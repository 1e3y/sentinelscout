from __future__ import annotations

from app.core.db import get_db


def test_readiness_succeeds_with_db_available(client):
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["configuration"] == "ok"
    assert "traceback" not in response.text.lower()


def test_readiness_fails_cleanly_when_db_unavailable(client, db_session):
    class BrokenSession:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("db down")

        def close(self):
            return None

    def _broken_db():
        yield BrokenSession()

    client.app.dependency_overrides[get_db] = _broken_db
    try:
        response = client.get("/ready")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert body["checks"]["database"] == "unavailable"
        assert "RuntimeError" not in response.text
        assert "Traceback" not in response.text
    finally:
        def _restore():
            try:
                yield db_session
            finally:
                pass

        client.app.dependency_overrides[get_db] = _restore
