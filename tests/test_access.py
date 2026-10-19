import pytest
from flask import Flask

from core.access import COOKIE, AccessGuard, protect
from core.store import TrafficStore
from sniffer import create_app

TOKEN = "correct-horse-battery-staple"


@pytest.fixture
def client():
    return create_app(TrafficStore(), token=TOKEN).test_client()


def test_api_and_dashboard_are_locked_without_the_code(client):
    api = client.get("/api/stats")
    assert api.status_code == 401
    assert "Access code required" in api.get_json()["error"]
    page = client.get("/")
    assert page.status_code == 401
    assert b'action="/login"' in page.data
    assert b"Packet Sniffer Dashboard" in page.data


def test_the_printed_link_unlocks_and_leaves_the_address_bar(client):
    response = client.get(f"/?token={TOKEN}")
    assert response.status_code == 302 and response.headers["Location"] == "/"
    cookie = response.headers["Set-Cookie"]
    assert f"{COOKIE}={TOKEN}" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert client.get("/api/stats").status_code == 200
    page = client.get("/")
    assert page.status_code == 200
    page.close()


def test_the_login_form(client):
    wrong = client.post("/login", data={"token": "guess"})
    assert wrong.status_code == 401 and b"Wrong access code" in wrong.data
    right = client.post("/login", data={"token": TOKEN})
    assert right.status_code == 303
    assert client.get("/api/alerts").status_code == 200


def test_stylesheet_is_public_but_still_gets_security_headers(client):
    css = client.get("/static/style.css")
    assert css.status_code == 200
    headers = css.headers
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert (headers["X-Frame-Options"], headers["X-Content-Type-Options"]) == ("DENY", "nosniff")
    css.close()
    assert client.get("/api/stats").headers["Cache-Control"] == "no-store"


def test_guessing_is_locked_out_for_a_minute():
    clock = [1000.0]
    guard = AccessGuard(TOKEN, max_failures=5, lockout_seconds=60, clock=lambda: clock[0])
    for _ in range(5):
        assert not guard.try_code("10.0.0.9", "guess")
    assert not guard.try_code("10.0.0.9", TOKEN)          # even the right code waits
    assert guard.wait_seconds("10.0.0.9") == 61
    assert guard.try_code("10.0.0.7", TOKEN)              # other addresses are not affected
    clock[0] += 61
    assert guard.try_code("10.0.0.9", TOKEN)


def test_lockout_through_the_login_form():
    app = Flask(__name__)
    app.get("/")(lambda: "dashboard")
    protect(app, TOKEN)
    client = app.test_client()
    for _ in range(5):
        client.post("/login", data={"token": "guess"})
    locked = client.post("/login", data={"token": TOKEN})
    assert locked.status_code == 429 and b"Too many wrong codes" in locked.data


def test_without_a_token_the_dashboard_is_open():
    client = create_app(TrafficStore()).test_client()
    response = client.get("/api/stats")
    assert response.status_code == 200
    assert response.get_json()["version"] == "1.0.0"
