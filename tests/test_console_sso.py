# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Single sign-on for the admin console against a real (in-process) OpenID
Connect provider: the authorization code flow with PKCE, ID-token checks,
roles, sessions, sign-out, and the attacks each check exists for."""
import base64
import hashlib
import http.server
import json
import threading
import time
import urllib.parse

import pytest

pytest.importorskip("mcp")
jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from tokenis.calllog import SqliteCallLog
from tokenis.config import ConfigError, parse_config
from tokenis.console_auth import SESSION_COOKIE, OidcClient, OidcSettings, SessionSigner
from tokenis.gateway.demo import demo_service
from tokenis.mcp_server.server import create_server, fixed_principal
from tokenis.ops import Metrics, install_routes
from tokenis.server_auth import ApiKeyStore

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ADMIN_TOKEN = "break-glass-token-0123456789"
WRITE = {"Content-Type": "application/json", "X-Tokenis-Console": "1"}


class FakeIdP:
    """Discovery, /authorize (issues a code for the next configured user),
    /token (checks PKCE and client auth, signs an ID token) and /jwks."""

    def __init__(self):
        self.user = {"sub": "u1", "email": "alice@acme.example", "email_verified": True}
        self.codes = {}
        self.tamper = {}
        idp = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _json(self, obj, status=200):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = self.path.partition("?")[0]
                if path == "/.well-known/openid-configuration":
                    return self._json({"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize",
                                       "token_endpoint": idp.issuer + "/token", "jwks_uri": idp.issuer + "/jwks",
                                       "id_token_signing_alg_values_supported": ["RS256"]})
                if path == "/jwks":
                    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
                    return self._json({"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]})
                return self._json({"error": "not found"}, 404)

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                grant = idp.codes.pop(form.get("code"), None)
                challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                auth = self.headers.get("Authorization", "")
                if grant is None or challenge != grant["challenge"] or auth != idp.expected_auth:
                    return self._json({"error": "invalid_grant"}, 400)
                now = int(time.time())
                claims = {"iss": idp.issuer, "aud": "tokenis-console", "iat": now, "exp": now + 300,
                          "nonce": grant["nonce"], **grant["user"], **idp.tamper.get("claims", {})}
                alg = idp.tamper.get("alg", "RS256")
                key = "shared-secret" if alg == "HS256" else KEY
                token = jwt.encode(claims, key, algorithm=alg, headers={"kid": "k1"})
                return self._json({"id_token": token, "access_token": "x", "token_type": "Bearer"})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.expected_auth = "Basic " + base64.b64encode(b"tokenis-console:s3cret").decode()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def authorize(self, url):
        """What the browser does at the IdP: sign in and come back with a code."""
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        assert q["code_challenge_method"] == "S256" and q["response_type"] == "code"
        code = f"code-{len(self.codes)}-{time.time()}"
        self.codes[code] = {"challenge": q["code_challenge"], "nonce": q["nonce"], "user": dict(self.user)}
        return code, q["state"]


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.server.shutdown()
    server.server.server_close()


def console(tmp_path, idp, **overrides):
    settings = OidcSettings(issuer=idp.issuer, client_id="tokenis-console", client_secret="s3cret",
                            redirect_url="http://testserver/admin/auth/callback", roles_claim="groups",
                            admins=("alice@acme.example",), auditors=("group:auditors",),
                            viewers=("vic@acme.example",), **overrides)
    service = demo_service(latency_granularity_ms=1.0)
    calls = SqliteCallLog(":memory:", service.settings.tenant)
    keys = ApiKeyStore(tmp_path / "keys.json")
    metrics = Metrics()
    server = create_server(service, principal_resolver=fixed_principal("alice"), metrics=metrics, call_log=calls)
    install_routes(server, service, metrics, admin_token=ADMIN_TOKEN, key_store=keys, call_log=calls,
                   oidc=OidcClient(settings), session_key=b"k" * 32)
    return TestClient(server.streamable_http_app(), follow_redirects=False), calls


def sign_in(client, idp, user=None):
    if user is not None:
        idp.user = user
    start = client.get("/admin/auth/start")
    assert start.status_code == 302
    code, state = idp.authorize(start.headers["location"])
    return client.get(f"/admin/auth/callback?code={code}&state={state}")


def test_unauthenticated_visitors_are_sent_to_sign_in(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    page = client.get("/admin")
    assert page.status_code == 302 and page.headers["location"] == "/admin/auth/login"
    api = client.get("/admin/api/summary")
    assert api.status_code == 401 and api.json()["login"] == "admin/auth/login"


def test_the_sign_in_page_is_the_consoles_own(tmp_path, idp):
    client, _ = console(tmp_path, idp, display_name="Acme <SSO>")
    page = client.get("/admin/auth/login")
    assert page.status_code == 200 and 'href="/admin/auth/start"' in page.text
    assert "Continue with Acme &lt;SSO&gt;" in page.text and "<SSO>" not in page.text  # escaped
    assert "nonce-" in page.headers["content-security-policy"]
    sign_in(client, idp)
    already = client.get("/admin/auth/login")  # signed in: straight to the console
    assert already.status_code == 302 and already.headers["location"] == "/admin"


def test_admin_signs_in_and_is_named_in_the_activity_log(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    done = sign_in(client, idp)
    assert done.status_code == 302 and done.headers["location"] == "/admin"
    cookie = next(c for c in done.headers.get_list("set-cookie") if c.startswith(SESSION_COOKIE))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/admin" in cookie
    assert client.get("/admin").status_code == 200
    me = client.get("/admin/api/summary").json()["me"]
    assert me == {"identity": "alice@acme.example", "role": "admin", "method": "sso", "sso": True}
    created = client.post("/admin/api/keys", headers=WRITE, content=json.dumps({"principal": "bot-1"}))
    assert created.status_code == 201
    events = client.get("/admin/api/activity").json()["events"]
    assert [(e["action"], e["actor"]) for e in events[:2]] == [
        ("create key", "alice@acme.example (admin)"), ("sign in", "alice@acme.example (admin)")]


def test_roles_are_enforced_by_the_server(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    sign_in(client, idp, {"sub": "u2", "email": "aud@acme.example", "email_verified": True, "groups": ["auditors"]})
    assert client.get("/admin/api/summary").json()["me"]["role"] == "auditor"
    assert client.get("/admin/api/principals").status_code == 200
    assert client.get("/admin/api/export/audit.csv").status_code == 200
    denied = client.post("/admin/api/keys", headers=WRITE, content=json.dumps({"principal": "x"}))
    assert denied.status_code == 403 and "admin role" in denied.json()["error"]

    viewer, _ = console(tmp_path, idp)
    sign_in(viewer, idp, {"sub": "u3", "email": "vic@acme.example", "email_verified": True})
    summary = viewer.get("/admin/api/summary").json()
    assert summary["me"]["role"] == "viewer" and "recent" not in summary and "api_keys" not in summary
    assert "stats" in summary
    for path in ("/admin/api/principals", "/admin/api/activity", "/admin/api/export/calls.csv"):
        assert viewer.get(path).status_code == 403


def test_people_without_a_role_are_refused_and_logged(tmp_path, idp):
    client, calls = console(tmp_path, idp)
    refused = sign_in(client, idp, {"sub": "u4", "email": "eve@elsewhere.example", "email_verified": True})
    assert refused.status_code == 403 and "eve@elsewhere.example" in refused.text
    assert SESSION_COOKIE not in refused.headers.get("set-cookie", "")
    assert calls.admin_events()[0]["action"] == "sign-in refused"
    unverified = sign_in(client, idp, {"sub": "u5", "email": "alice@acme.example", "email_verified": False})
    assert unverified.status_code == 403  # an unverified address is not the admin's


def test_forged_or_replayed_sign_ins_fail(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    start = client.get("/admin/auth/start")
    code, state = idp.authorize(start.headers["location"])
    assert client.get(f"/admin/auth/callback?code={code}&state=forged").status_code == 400  # CSRF on login
    fresh = TestClient(client.app, follow_redirects=False)  # no flow cookie: another browser
    assert fresh.get(f"/admin/auth/callback?code={code}&state={state}").status_code == 400
    ok = client.get(f"/admin/auth/callback?code={code}&state={state}")
    assert ok.status_code == 302
    assert client.get(f"/admin/auth/callback?code={code}&state={state}").status_code == 400  # replay

    for tamper, reason in (({"claims": {"nonce": "other"}}, "not issued for this sign-in"),
                           ({"claims": {"aud": "someone-else"}}, "did not verify"),
                           ({"claims": {"iss": "https://evil.example"}}, "did not verify"),
                           ({"alg": "HS256"}, "did not verify")):
        idp.tamper = tamper
        attacker = TestClient(client.app, follow_redirects=False)
        result = sign_in(attacker, idp, dict(idp.user))
        assert result.status_code == 400 and reason in result.text, tamper
        assert attacker.get("/admin/api/summary").status_code == 401
    idp.tamper = {}


def test_sessions_cannot_be_forged_and_sign_out_ends_them(tmp_path, idp):
    client, calls = console(tmp_path, idp)
    forged = SessionSigner(b"x" * 32, "session").sign({"sub": "mallory", "role": "admin"}, 3600)
    client.cookies.set(SESSION_COOKIE, forged, path="/admin")
    assert client.get("/admin/api/summary").status_code == 401
    client.cookies.clear()
    expired = SessionSigner(b"k" * 32, "session").sign({"sub": "alice@acme.example", "role": "admin"}, -1)
    client.cookies.set(SESSION_COOKIE, expired, path="/admin")
    assert client.get("/admin/api/summary").status_code == 401
    client.cookies.clear()

    sign_in(client, idp)
    assert client.post("/admin/auth/logout", headers={"Content-Type": "application/json"}, content="{}").status_code == 403
    out = client.post("/admin/auth/logout", headers=WRITE, content="{}")
    assert out.status_code == 200 and "Max-Age=0" in out.headers["set-cookie"]
    assert client.get("/admin/api/summary").status_code == 401
    assert calls.admin_events()[0]["action"] == "sign out"


def test_the_admin_token_still_works_for_automation(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    me = client.get("/admin/api/summary", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}).json()["me"]
    assert me["identity"] == "admin token" and me["role"] == "admin"


def test_identity_provider_outage_shows_a_page(tmp_path, idp):
    client, _ = console(tmp_path, idp)
    idp.server.shutdown()
    idp.server.server_close()
    page = client.get("/admin/auth/start")
    assert page.status_code == 503 and "Sign-in is unavailable" in page.text


def test_oidc_configuration_is_validated(tmp_path):
    base = {"tenant": {"name": "t"}, "data": {"path": "d.csv"},
            "columns": [{"name": "v", "protection": "sealed"}, {"name": "g", "protection": "open"}],
            "server": {"transport": "http", "public_url": "https://tokenis.example.com"},
            "auth": {"mode": "api_keys", "api_keys_file": "k.json"}}

    def parse(oidc):
        return parse_config({**base, "ops": {"oidc": oidc}}, tmp_path)

    cfg = parse({"issuer": "https://login.example.com", "client_id": "c", "admins": ["a@x.example"]})
    assert cfg.ops.oidc.redirect_url == "https://tokenis.example.com/admin/auth/callback"
    for bad, message in (({"client_id": "c", "admins": ["a"]}, "issuer"),
                         ({"issuer": "http://login.example.com", "client_id": "c", "admins": ["a"]}, "https"),
                         ({"issuer": "https://l.example", "client_id": "c"}, "nobody"),
                         ({"issuer": "https://l.example", "client_id": "c", "admins": "a"}, "list"),
                         ({"issuer": "https://l.example", "client_id": "c", "admins": ["a"], "scopes": ["email"]}, "openid"),
                         ({"issuer": "https://l.example", "client_id": "c", "admins": ["a"], "session_hours": 72}, "session_hours")):
        with pytest.raises(ConfigError, match=message):
            parse(bad)


def test_only_https_or_loopback_endpoints_are_used():
    with pytest.raises(ValueError):
        OidcClient(OidcSettings(issuer="file://localhost/etc", client_id="c", admins=("a",)))
    with pytest.raises(ValueError):
        OidcClient(OidcSettings(issuer="http://idp.example.com", client_id="c", admins=("a",)))
