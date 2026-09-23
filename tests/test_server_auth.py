# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import os
import stat
import time

import pytest

pytest.importorskip("mcp", reason="needs the `server` extra (Python >= 3.10)")
jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tokenis.server_auth import (
    TOKEN_PREFIX,
    ApiKeyStore,
    ApiKeyVerifier,
    JwtVerifier,
    validate_principal,
)


def run(coro):
    return asyncio.run(coro)


# -- API keys ------------------------------------------------------------------------


def test_api_key_lifecycle(tmp_path):
    path = tmp_path / "keys.json"
    store = ApiKeyStore(path)
    token, record = store.create("alice@example.com")
    assert token.startswith(TOKEN_PREFIX) and len(token) > 40
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert token not in path.read_text()  # only the hash is stored
    assert store.verify(token) == "alice@example.com"
    assert store.verify(token + "x") is None
    assert store.verify("not-a-key") is None

    access = run(ApiKeyVerifier(store).verify_token(token))
    assert access.subject == "alice@example.com"
    assert run(ApiKeyVerifier(store).verify_token("tkn_wrong")) is None

    # Revocation is picked up by a separate store instance (a running server).
    other = ApiKeyStore(path)
    assert other.verify(token) == "alice@example.com"
    assert store.revoke(record.key_id)
    time.sleep(0.01)
    os.utime(path)  # make sure the mtime moves even on coarse filesystems
    assert other.verify(token) is None
    assert not store.revoke(record.key_id)
    assert [r.public_view()["revoked"] for r in other.list()] == [True]
    assert "key_hash" not in json.dumps([r.public_view() for r in other.list()])


def test_principals_are_identifiers():
    assert validate_principal("svc:reporting-bot") == "svc:reporting-bot"
    for bad in ("", "a b", "x" * 129, "evil\nlog-line", "ünïcode"):
        with pytest.raises(ValueError):
            validate_principal(bad)


# -- JWT -------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def make_verifier(public, **kwargs):
    return JwtVerifier(
        issuer="https://idp.example.com/", audience="tokenis",
        key_resolver=lambda _token: public, algorithms=("RS256",), **kwargs,
    )


def sign(private, **claims):
    now = int(time.time())
    body = {"iss": "https://idp.example.com/", "aud": "tokenis", "sub": "alice@example.com",
            "exp": now + 300, "iat": now, **claims}
    return jwt.encode({k: v for k, v in body.items() if v is not None}, private, algorithm="RS256")


def test_valid_jwt(keypair):
    private, public = keypair
    access = run(make_verifier(public).verify_token(sign(private, scope="tokenis.query other")))
    assert access.subject == "alice@example.com"
    assert access.scopes == ["tokenis.query", "other"]


@pytest.mark.parametrize("claims", [
    {"exp": int(time.time()) - 3600},        # expired
    {"aud": "someone-else"},                  # wrong audience
    {"iss": "https://evil.example.com/"},     # wrong issuer
    {"exp": None},                            # no expiry at all
    {"sub": "has spaces"},                    # not a valid principal
])
def test_invalid_jwts_are_rejected(keypair, claims):
    private, public = keypair
    assert run(make_verifier(public).verify_token(sign(private, **claims))) is None


def test_required_scopes(keypair):
    private, public = keypair
    verifier = make_verifier(public, required_scopes=("tokenis.query",))
    assert run(verifier.verify_token(sign(private, scope="other"))) is None
    assert run(verifier.verify_token(sign(private, scp=["tokenis.query"]))) is not None


def test_algorithm_confusion_and_alg_none_are_rejected(keypair):
    _private, public = keypair
    pem = public.public_bytes(serialization.Encoding.PEM,
                              serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    claims = {"iss": "https://idp.example.com/", "aud": "tokenis", "sub": "mallory",
              "exp": now + 300}
    import base64

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    # HS256 "signed" with the public key as the HMAC secret.
    import hashlib
    import hmac

    head = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64(claims)
    sig = base64.urlsafe_b64encode(hmac.new(pem, head.encode(), hashlib.sha256).digest())
    confused = head + "." + sig.rstrip(b"=").decode()
    unsigned = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + "."
    verifier = make_verifier(public)
    assert run(verifier.verify_token(confused)) is None
    assert run(verifier.verify_token(unsigned)) is None
    with pytest.raises(ValueError, match="asymmetric"):
        JwtVerifier(issuer="i", audience="a", key_resolver=lambda _t: pem, algorithms=("HS256",))
    with pytest.raises(ValueError, match="https"):
        JwtVerifier(issuer="i", audience="a", jwks_url="http://idp.example.com/jwks")
