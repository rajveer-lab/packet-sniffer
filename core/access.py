"""Keep the dashboard and its API private.

Captured packets show what every device on the network is doing, so the
dashboard asks for an access code. A new random code is made at every start
(or chosen with --token) and printed in the terminal as a ready-made link:

    Dashboard: http://localhost:5000/?token=Xy3...

Opening that link stores the code in a cookie (HttpOnly, SameSite=Strict, so
page scripts and other sites cannot read or send it) and takes the code back
out of the address bar. Without the cookie the API answers 401 and the page
shows a form asking for the code. After 5 wrong codes from one address, that
address has to wait a minute before trying again.

Every response also gets headers that stop the page being framed by another
site, its files being read as another content type, or it loading scripts
from anywhere but this server.
"""

import hmac
import secrets
import time
from html import escape

from flask import jsonify, make_response, redirect, request

COOKIE = "sniffer_access"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Packet Sniffer Dashboard</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body class="locked">
  <main class="lock-card">
    <div class="layers"><span>ETH</span><span>IP</span><span>TCP/UDP</span></div>
    <h1>Packet Sniffer Dashboard</h1>
    <p>Captured traffic is private. Open the link printed in the terminal where
    sniffer.py is running, or type the access code shown there.</p>
    <form method="post" action="/login">
      <label for="token">Access code</label>
      <input id="token" name="token" autocomplete="off" spellcheck="false" autofocus required>
      <button type="submit">Unlock</button>
    </form>
    {message}
  </main>
</body>
</html>
"""


def new_token():
    """A random access code: 128 bits, URL-safe, impossible to guess."""
    return secrets.token_urlsafe(16)


def add_security_headers(response):
    response.headers.update(SECURITY_HEADERS)
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


class AccessGuard:
    """Checks access codes and slows down anyone guessing them."""

    def __init__(self, token, max_failures=5, lockout_seconds=60, clock=time.monotonic):
        self._token = token.encode()
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures = {}   # address -> (wrong guesses, time of the last one)

    def matches(self, candidate):
        # compare_digest takes the same time however much of the code is right
        return bool(candidate) and hmac.compare_digest(candidate.encode(), self._token)

    def wait_seconds(self, address):
        count, last = self._failures.get(address, (0, 0))
        if count < self.max_failures:
            return 0
        remaining = self.lockout_seconds - (self._clock() - last)
        if remaining <= 0:
            del self._failures[address]
            return 0
        return int(remaining) + 1

    def try_code(self, address, candidate):
        """True if the code is right; wrong codes count towards a lockout."""
        if self.wait_seconds(address):
            return False
        if self.matches(candidate):
            self._failures.pop(address, None)
            return True
        count, _ = self._failures.get(address, (0, 0))
        self._failures[address] = (count + 1, self._clock())
        return False


def protect(app, token, clock=time.monotonic):
    """Require the access code for the dashboard page and every API call."""
    guard = AccessGuard(token, clock=clock)

    def unlocked(response):
        response.set_cookie(COOKIE, token, httponly=True, samesite="Strict", path="/")
        return response

    def login_page(message="", status=401):
        html = LOGIN_PAGE.format(message=f'<p class="lock-error">{escape(message)}</p>' if message else "")
        return make_response(html, status)

    @app.before_request
    def require_access_code():
        if request.endpoint == "static" or request.path == "/login":
            return None   # the login form needs the stylesheet; the code is public on GitHub anyway
        if guard.matches(request.cookies.get(COOKIE, "")):
            return None
        address = request.remote_addr or "?"
        if request.path == "/" and "token" in request.args:
            if guard.try_code(address, request.args["token"]):
                return unlocked(redirect("/"))
            return login_page("That link has an old or wrong access code.")
        if request.path.startswith("/api/"):
            return jsonify(error="Access code required. Open the link printed by sniffer.py."), 401
        return login_page()

    @app.post("/login")
    def login():
        address = request.remote_addr or "?"
        if guard.try_code(address, request.form.get("token", "").strip()):
            return unlocked(redirect("/", code=303))
        wait = guard.wait_seconds(address)
        if wait:
            return login_page(f"Too many wrong codes. Try again in {wait} seconds.", 429)
        return login_page("Wrong access code.")

    return guard
