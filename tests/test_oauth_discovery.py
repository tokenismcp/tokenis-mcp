# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""OAuth discovery for AI apps that sign in with OAuth rather than an API key
(ChatGPT's custom connectors, and other MCP clients): the gateway answers an
unauthenticated call with 401 and points at its protected-resource metadata,
which names the identity provider (RFC 9728 / the MCP authorization spec)."""
import pytest

pytest.importorskip("mcp")
from mcp.server.auth.settings import AuthSettings
from starlette.testclient import TestClient

from tokenis.gateway.demo import demo_service
from tokenis.mcp_server.server import create_server
from tokenis.server_auth import JwtVerifier, authenticated_principal

ISSUER = "https://login.example.com/"
RESOURCE = "https://tokenis.example.com/mcp"


@pytest.fixture
def client():
    verifier = JwtVerifier(issuer=ISSUER, audience="tokenis", jwks_url=ISSUER + "jwks.json",
                           algorithms=("RS256",), principal_claim="sub", required_scopes=())
    auth = AuthSettings(issuer_url=ISSUER, resource_server_url=RESOURCE, required_scopes=None,
                        validate_token_resource=False)
    server = create_server(demo_service(latency_granularity_ms=1.0), principal_resolver=authenticated_principal,
                           token_verifier=verifier, auth=auth)
    return TestClient(server.streamable_http_app(), base_url="https://tokenis.example.com")


def test_an_unauthenticated_call_points_at_the_resource_metadata(client):
    response = client.post("/mcp", json={}, headers={"Accept": "application/json, text/event-stream"})
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "resource_metadata=" in challenge and "/.well-known/oauth-protected-resource/mcp" in challenge


def test_the_resource_metadata_names_the_identity_provider(client):
    metadata = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert metadata["resource"] == RESOURCE
    assert metadata["authorization_servers"] == [ISSUER]
    assert metadata["bearer_methods_supported"] == ["header"]
