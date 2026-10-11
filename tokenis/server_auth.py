# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Authentication for the Tokenis MCP server's HTTP transport.

The gateway's admission budgets and audit trace are keyed by *principal*, so
the principal must come from verified credentials, never from anything a
model can put in a tool argument (P4 Theorem 13 / Corollary 14). Two
verifiers are provided, both implementing the ``mcp`` SDK's
``TokenVerifier`` protocol so the SDK's own bearer-token middleware rejects
unauthenticated requests with 401 before any tool runs:

- `ApiKeyVerifier`: static API keys, one or more per principal, managed with
  ``tokenis-mcp keys create/list/revoke``. Only SHA-256 hashes are stored
  (keys are 256-bit random, so a slow KDF adds nothing); verification
  compares against every stored hash in constant time; the key file is
  re-read when it changes, so revocation needs no restart.
- `JwtVerifier`: tokens from an enterprise identity provider (Okta, Entra ID,
  Auth0, Keycloak...), verified against its JWKS. Only asymmetric algorithms
  are accepted (no ``none``, no HMAC -- the classic algorithm-confusion
  attack), and ``exp``, ``iss`` and ``aud`` are required.

`authenticated_principal` is the principal resolver to pair with either.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import anyio.to_thread

from tokenis.safe import equal

log = logging.getLogger("tokenis.auth")

TOKEN_PREFIX = "tkn_"  # noqa: S105 -- a key-format prefix, not a credential
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@:+-]{1,128}$")
_ASYMMETRIC_ALGORITHMS = (
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
)


class AuthenticationRequired(PermissionError):
    """Raised when a tool runs without a verified principal."""


def validate_principal(principal: str) -> str:
    """Principals are identifiers, not free text: 1-128 characters from
    ``[A-Za-z0-9._@:+-]``. Keeps them safe to log and to use as budget keys."""
    if not isinstance(principal, str) or not _PRINCIPAL_RE.match(principal):
        raise ValueError("principal must be 1-128 characters from [A-Za-z0-9._@:+-]")
    return principal


def _hash_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str
    principal: str
    key_hash: str
    created_at: int
    revoked: bool = False

    def public_view(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "principal": self.principal,
            "created_at": self.created_at,
            "revoked": self.revoked,
        }


class ApiKeyStore:
    """API keys persisted as SHA-256 hashes in a JSON file (mode 0600).

    Thread-safe; re-reads the file when its modification time changes."""

    def __init__(self, path: os.PathLike[str] | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._records: List[ApiKeyRecord] = []
        self._mtime: Optional[int] = None
        self._reload_if_changed()

    # -- persistence --------------------------------------------------------

    def _reload_if_changed(self) -> None:
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            self._records, self._mtime = [], None
            return
        if mtime == self._mtime:
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("version") != 1:
            raise ValueError(f"{self.path}: unsupported key file version")
        self._records = [ApiKeyRecord(**r) for r in data.get("keys", [])]
        self._mtime = mtime

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"version": 1, "keys": [asdict(r) for r in self._records]}, indent=2
        )
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tokenis-keys-")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self._mtime = self.path.stat().st_mtime_ns

    # -- management ---------------------------------------------------------

    def create(self, principal: str) -> Tuple[str, ApiKeyRecord]:
        """Create a key for ``principal``. The plaintext key is returned
        exactly once and never stored."""
        validate_principal(principal)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        key_hash = _hash_key(token)
        record = ApiKeyRecord(
            key_id=key_hash[:12], principal=principal, key_hash=key_hash, created_at=int(time.time())
        )
        with self._lock:
            self._reload_if_changed()
            self._records.append(record)
            self._save()
        return token, record

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            found = False
            updated = []
            for r in self._records:
                if r.key_id == key_id and not r.revoked:
                    r = ApiKeyRecord(r.key_id, r.principal, r.key_hash, r.created_at, revoked=True)
                    found = True
                updated.append(r)
            if found:
                self._records = updated
                self._save()
            return found

    def list(self) -> List[ApiKeyRecord]:
        with self._lock:
            self._reload_if_changed()
            return list(self._records)

    # -- verification -------------------------------------------------------

    def verify(self, token: str) -> Optional[str]:
        """The principal for ``token``, or None. Compares against every
        stored hash (no early exit) in constant time."""
        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > 256:
            return None
        candidate = _hash_key(token)
        with self._lock:
            self._reload_if_changed()
            records = list(self._records)
        principal: Optional[str] = None
        for r in records:
            if equal(candidate, r.key_hash) and not r.revoked:
                principal = r.principal
        return principal


class ApiKeyVerifier:
    """``mcp`` ``TokenVerifier`` backed by an `ApiKeyStore`."""

    def __init__(self, store: Any) -> None:
        self.store = store

    async def verify_token(self, token: str) -> Any:
        import anyio
        from mcp.server.auth.provider import AccessToken

        # The store may do blocking I/O (a file, or the shared database): keep
        # it off the event loop so one slow lookup cannot stall every request.
        try:
            principal = await anyio.to_thread.run_sync(self.store.verify, token)
        except Exception as exc:  # noqa: BLE001 -- any store failure means "cannot tell"
            # The key store is unreachable (e.g. the database restarting):
            # neither "valid" nor "invalid" is true, so answer 503, not 401.
            from tokenis.gateway.service import GatewayUnavailable

            log.warning("API key store unavailable: %s", type(exc).__name__)
            raise GatewayUnavailable("credential store unavailable") from None
        if principal is None:
            return None
        return AccessToken(token=token, client_id=principal, scopes=["tokenis"], subject=principal)


class JwtVerifier:
    """``mcp`` ``TokenVerifier`` for IdP-issued JWTs.

    ``key_resolver`` maps a raw token to its verification key; by default it
    is PyJWT's ``PyJWKClient(jwks_url)`` (cached). ``required_scopes`` are
    checked against the ``scope`` (space-separated) or ``scp`` (list) claim.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: Optional[str] = None,
        key_resolver: Optional[Callable[[str], Any]] = None,
        algorithms: Sequence[str] = ("RS256", "ES256"),
        principal_claim: str = "sub",
        required_scopes: Sequence[str] = (),
        leeway_seconds: int = 30,
    ) -> None:
        import jwt

        bad = [a for a in algorithms if a not in _ASYMMETRIC_ALGORITHMS]
        if bad:
            raise ValueError(f"only asymmetric JWT algorithms are allowed, got {bad}")
        if key_resolver is None:
            if not jwks_url:
                raise ValueError("JwtVerifier needs jwks_url or key_resolver")
            if not jwks_url.startswith("https://"):
                raise ValueError("jwks_url must be https://")
            client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

            def key_resolver(token: str) -> Any:
                return client.get_signing_key_from_jwt(token).key

        self._jwt = jwt
        self._resolve_key = key_resolver
        self.issuer = issuer
        self.audience = audience
        self.algorithms = list(algorithms)
        self.principal_claim = principal_claim
        self.required_scopes = list(required_scopes)
        self.leeway = leeway_seconds

    def _decode(self, token: str) -> Optional[Dict[str, Any]]:
        jwt = self._jwt
        try:
            key = self._resolve_key(token)
            claims: Dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iss", "aud"]},
            )
        except (jwt.PyJWTError, ValueError, KeyError):
            return None
        return claims

    async def verify_token(self, token: str) -> Any:
        from mcp.server.auth.provider import AccessToken

        claims = await anyio.to_thread.run_sync(self._decode, token)
        if claims is None:
            return None
        principal = claims.get(self.principal_claim)
        if not isinstance(principal, str):
            return None
        try:
            validate_principal(principal)
        except ValueError:
            return None
        scope_claim = claims.get("scope", claims.get("scp", []))
        scopes = scope_claim.split() if isinstance(scope_claim, str) else list(scope_claim or [])
        if any(s not in scopes for s in self.required_scopes):
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or principal),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            subject=principal,
            claims=claims,
        )


def authenticated_principal(_ctx: Any) -> str:
    """Principal resolver for an authenticated HTTP server: the verified
    token's subject, or `AuthenticationRequired`."""
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None or not token.subject:
        raise AuthenticationRequired("no verified credentials on this request")
    return token.subject
