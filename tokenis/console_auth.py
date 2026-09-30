# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Single sign-on for the admin console: OpenID Connect (authorization code
flow with PKCE) against the organisation's identity provider -- Okta, Entra
ID, Google Workspace, Keycloak, Auth0, Dex, ... -- and three roles:

- ``viewer``: overview statistics, replicas and the policy in force;
- ``auditor``: also per-user activity, the audit trail, exports and the
  admin activity log;
- ``admin``: also issues and revokes API keys.

Roles come from the configuration: each role lists identities (the
``identity_claim``, e.g. an e-mail address) and/or group values (entries of
``roles_claim`` in the ID token, e.g. an IdP group). Anyone who signs in but
matches no list is refused.

Sessions are stateless, HMAC-signed cookies (HttpOnly, SameSite=Lax, Secure
on https), valid on every replica because all replicas share the signing
key: derived from the keystore's audit key, or ``session_secret_env``.
Signing out clears the cookie; a session ends after ``session_hours``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

ROLES = ("viewer", "auditor", "admin")
RANK = {role: i for i, role in enumerate(ROLES)}
SESSION_COOKIE = "tokenis_console"
FLOW_COOKIE = "tokenis_oidc"
_ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")


class ConsoleAuthError(Exception):
    """Sign-in failed (shown to the person signing in, without internals)."""


def at_least(role: Optional[str], needed: str) -> bool:
    return role is not None and RANK.get(role, -1) >= RANK[needed]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _allowed_url(url: str) -> bool:
    """https anywhere; plain http only to this machine (local development).
    Nothing else -- in particular no file: or custom schemes."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")


class SessionSigner:
    """Signed, expiring, tamper-evident cookie values (not encrypted: they
    carry only who is signed in and their role)."""

    def __init__(self, key: bytes, purpose: str) -> None:
        if len(key) < 16:
            raise ValueError("session key too short")
        self._key = hmac.new(key, b"tokenis-console:" + purpose.encode(), hashlib.sha256).digest()

    def sign(self, payload: Dict[str, Any], ttl_seconds: int) -> str:
        body = _b64(json.dumps({**payload, "exp": int(time.time()) + ttl_seconds},
                               separators=(",", ":"), sort_keys=True).encode())
        mac = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{mac}"

    def verify(self, value: Optional[str]) -> Optional[Dict[str, Any]]:
        if not value or value.count(".") != 1 or len(value) > 4096:
            return None
        body, mac = value.split(".")
        expected = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, expected):
            return None
        try:
            payload = json.loads(_unb64(body))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict) or int(payload.get("exp", 0)) < time.time():
            return None
        return payload


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    client_id: str
    client_secret: Optional[str] = None
    redirect_url: str = ""
    scopes: Tuple[str, ...] = ("openid", "email", "profile")
    identity_claim: str = "email"
    roles_claim: Optional[str] = None
    admins: Tuple[str, ...] = ()
    auditors: Tuple[str, ...] = ()
    viewers: Tuple[str, ...] = ()
    session_hours: float = 8.0

    def role_for(self, claims: Dict[str, Any]) -> Tuple[Optional[str], str]:
        """(role or None, identity) for verified ID-token claims."""
        identity = claims.get(self.identity_claim)
        if not isinstance(identity, str) or not identity:
            identity = str(claims.get("sub", ""))
        if self.identity_claim == "email" and claims.get("email_verified") is False:
            return None, identity
        groups: List[str] = []
        if self.roles_claim:
            raw = claims.get(self.roles_claim)
            groups = [raw] if isinstance(raw, str) else [str(g) for g in raw or [] if isinstance(g, str)]
        subjects = {identity.lower()} | {f"group:{g}" for g in groups}
        for role, members in (("admin", self.admins), ("auditor", self.auditors), ("viewer", self.viewers)):
            if subjects & {m.lower() if not m.startswith("group:") else m for m in members}:
                return role, identity
        return None, identity


class OidcClient:
    """Discovery, the authorization request, the code exchange and ID-token
    validation. Network calls use the standard library with timeouts."""

    def __init__(self, settings: OidcSettings, *, timeout: float = 10.0) -> None:
        if not _allowed_url(settings.issuer):
            raise ValueError("the OIDC issuer must be https:// (plain http only for localhost)")
        self.settings = settings
        self.timeout = timeout
        self._meta: Optional[Dict[str, Any]] = None
        self._meta_at = 0.0
        self._lock = threading.Lock()
        self._jwks: Any = None

    def _get_json(self, url: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        if not _allowed_url(url):
            raise ConsoleAuthError("the identity provider returned a non-https endpoint")
        req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})  # noqa: S310
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 -- scheme checked above
            return json.loads(resp.read().decode("utf-8"))

    def metadata(self) -> Dict[str, Any]:
        with self._lock:
            if self._meta is None or time.time() - self._meta_at > 3600:
                meta = self._get_json(self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration")
                if str(meta.get("issuer", "")).rstrip("/") != self.settings.issuer.rstrip("/"):
                    raise ConsoleAuthError("the identity provider's metadata names a different issuer")
                jwks_uri = str(meta.get("jwks_uri", ""))
                if not _allowed_url(jwks_uri):
                    raise ConsoleAuthError("the identity provider's key set is not served over https")
                self._meta, self._meta_at = meta, time.time()
                import jwt

                self._jwks = jwt.PyJWKClient(meta["jwks_uri"], cache_keys=True, lifespan=600,
                                             timeout=int(self.timeout))
            return self._meta

    def authorization_url(self, state: str, nonce: str, verifier: str) -> str:
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": self.settings.client_id,
            "redirect_uri": self.settings.redirect_url, "scope": " ".join(self.settings.scopes),
            "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
        })
        endpoint = self.metadata()["authorization_endpoint"]
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{query}"

    def exchange(self, code: str, verifier: str, nonce: str) -> Dict[str, Any]:
        """Redeem the code and return the ID token's verified claims."""
        import jwt

        meta = self.metadata()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.settings.redirect_url,
                "code_verifier": verifier, "client_id": self.settings.client_id}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.settings.client_secret:
            basic = base64.b64encode(
                f"{urllib.parse.quote(self.settings.client_id, safe='')}:"
                f"{urllib.parse.quote(self.settings.client_secret, safe='')}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        try:
            tokens = self._get_json(meta["token_endpoint"], urllib.parse.urlencode(form).encode(), headers)
        except urllib.error.HTTPError as exc:
            exc.close()  # an HTTPError holds the open response
            raise ConsoleAuthError(f"the identity provider refused the sign-in (HTTP {exc.code})") from None
        id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not isinstance(id_token, str):
            raise ConsoleAuthError("the identity provider returned no ID token")
        algorithms = [a for a in meta.get("id_token_signing_alg_values_supported", ["RS256"]) if a in _ALLOWED_ALGS]
        try:
            key = self._jwks.get_signing_key_from_jwt(id_token).key
            claims: Dict[str, Any] = jwt.decode(
                id_token, key, algorithms=algorithms or ["RS256"], audience=self.settings.client_id,
                issuer=meta["issuer"], leeway=60, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except (jwt.PyJWTError, KeyError, ValueError) as exc:
            raise ConsoleAuthError(f"the ID token did not verify ({type(exc).__name__})") from None
        if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise ConsoleAuthError("the ID token was not issued for this sign-in")
        return claims


def new_flow() -> Dict[str, str]:
    """State, nonce and PKCE verifier for one sign-in."""
    return {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
            "verifier": secrets.token_urlsafe(48)}


def parse_members(value: Any, where: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{where} must be a list of identities or \"group:NAME\" entries")
    return tuple(value)


def cookie_header(name: str, value: str, *, max_age: int, secure: bool, path: str = "/admin") -> str:
    parts = [f"{name}={value}", f"Path={path}", f"Max-Age={max_age}", "HttpOnly", "SameSite=Lax"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def expired_cookie(name: str, *, secure: bool, path: str = "/admin") -> str:
    return cookie_header(name, "", max_age=0, secure=secure, path=path)


def read_cookie(header: str, name: str) -> Optional[str]:
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None
