# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The Tokenis MCP server: wires :class:`tokenis.gateway.service.TokenisGatewayService`
to the seven tools and catalogue resource described in
``tokenis/spec/tool-surface.md``, over the official ``mcp`` Python SDK.

Principal resolution -- read this before deploying anything
-------------------------------------------------------------
Every tool here takes a ``ctx: Context`` parameter, which the ``mcp``
library injects automatically and which is *not* part of the tool's
model-visible JSON schema (unlike every other parameter). ``ctx`` is
resolved to an authenticated ``principal`` string via the
``principal_resolver`` passed to :func:`create_server`, and that resolved
string -- never anything the model supplies as a plain tool argument -- is
what reaches :class:`~tokenis.gateway.service.TokenisGatewayService`. This
is a direct, structural response to P4 Theorem 13 / Corollary 14
(credential-scoped or model-suppliable identity admits no containment
bound; the subject must be authenticated upstream).

:func:`demo_principal_resolver` (the default) is a stub that returns a
fixed string -- adequate for local examples and the test suite, **not** an
authentication mechanism. A real deployment must supply a resolver that
extracts a verified subject from ``ctx`` (e.g. from the session's OIDC/SAML
claims via the `mcp` SDK's own ``token_verifier``/``auth`` machinery), and
should refuse to start without one -- see the ``require_real_auth`` flag.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from mcp.server.mcpserver import Context, MCPServer

from tokenis.gateway.reveal import RevealDenied
from tokenis.gateway.service import AdmissionDenied, TokenisGatewayService, load_demo_ledger

PrincipalResolver = Callable[[Context], str]


def demo_principal_resolver(ctx: Context) -> str:
    """**Not authentication.** Returns a fixed demo subject regardless of
    who is actually calling. See the module docstring."""
    return "demo-principal"


def create_server(
    service: Optional[TokenisGatewayService] = None,
    principal_resolver: PrincipalResolver = demo_principal_resolver,
    require_real_auth: bool = False,
    name: str = "tokenis",
) -> MCPServer:
    """Build an :class:`MCPServer` exposing the Tokenis tool surface.

    ``require_real_auth=True`` refuses to construct the server with the
    default demo resolver still in place -- pass this in anything other
    than a local example/test.
    """
    if require_real_auth and principal_resolver is demo_principal_resolver:
        raise ValueError(
            "require_real_auth=True but principal_resolver is still the demo "
            "stub; pass a resolver backed by real authenticated session state"
        )

    if service is None:
        svc = TokenisGatewayService()
        load_demo_ledger(svc)
    else:
        svc = service
    mcp = MCPServer(
        name=name,
        description=(
            "Cryptographic disclosure-boundary gateway: operations over "
            "encrypted data, not access to the data itself. See "
            "tokenis/spec/tool-surface.md."
        ),
    )

    def _principal(ctx: Context) -> str:
        return principal_resolver(ctx)

    @mcp.tool(name="aggregate", description="SUM/COUNT/AVG over a sealed column, filtered by public attributes.")
    def aggregate_tool(
        ctx: Context, function: str, industry: Optional[str] = None, region: Optional[str] = None,
    ) -> dict:
        try:
            return svc.aggregate(_principal(ctx), function, industry=industry, region=region)
        except (AdmissionDenied, ValueError) as exc:
            return {"error": str(exc)}

    @mcp.tool(name="group_by", description="Aggregate partitioned by an OPEN attribute, k-suppressed per group.")
    def group_by_tool(ctx: Context, key: str) -> dict:
        try:
            return svc.group_by(_principal(ctx), key)
        except (AdmissionDenied, ValueError) as exc:
            return {"error": str(exc)}

    @mcp.tool(name="compare_periods", description="Direction/ratio-banded comparison between two aggregate periods.")
    def compare_periods_tool(
        ctx: Context, industry: str, period_a_multiplier: float, period_b_multiplier: float,
    ) -> dict:
        try:
            return svc.compare_periods(_principal(ctx), industry, period_a_multiplier, period_b_multiplier)
        except (AdmissionDenied, ValueError, ZeroDivisionError) as exc:
            return {"error": str(exc)}

    @mcp.tool(name="similarity_search", description="Top-k nearest customer tokens to a given token, by embedding similarity.")
    def similarity_search_tool(ctx: Context, query_token: str, top_k: int = 3) -> dict:
        try:
            return svc.similarity_search(_principal(ctx), query_token, top_k=top_k)
        except (AdmissionDenied, ValueError) as exc:
            return {"error": str(exc)}

    @mcp.tool(name="exists", description="Presence test for a record matching public attributes and/or a customer token.")
    def exists_tool(ctx: Context, industry: Optional[str] = None, customer_token: Optional[str] = None) -> dict:
        try:
            return svc.exists(_principal(ctx), industry=industry, customer_token=customer_token)
        except (AdmissionDenied, ValueError) as exc:
            return {"error": str(exc)}

    @mcp.tool(
        name="disclose_ratio",
        description=(
            "Discloses a numeric ratio between two aggregates. Crosses the "
            "disclosure boundary: gated and audited (P2 Definition 15). "
            "Requires an explicit, specific purpose string."
        ),
    )
    def disclose_ratio_tool(
        ctx: Context, numerator_industry: str, denominator_industry: str, purpose: str,
    ) -> dict:
        try:
            return svc.disclose_ratio(_principal(ctx), numerator_industry, denominator_industry, purpose)
        except (AdmissionDenied, RevealDenied, ValueError, ZeroDivisionError) as exc:
            return {"error": str(exc)}

    @mcp.tool(
        name="disclose_bucket",
        description=(
            "Discloses a threshold-bucket classification for an aggregate. "
            "Crosses the disclosure boundary: gated and audited."
        ),
    )
    def disclose_bucket_tool(
        ctx: Context, industry: str, thresholds: List[float], labels: List[str], purpose: str,
    ) -> dict:
        try:
            return svc.disclose_bucket(_principal(ctx), industry, thresholds, labels, purpose)
        except (AdmissionDenied, RevealDenied, ValueError) as exc:
            return {"error": str(exc)}

    @mcp.resource(
        "tokenis://catalogue",
        name="catalogue",
        description=(
            "Schema metadata only -- attribute names, protection classes, "
            "minimum aggregate sizes. No row values. Lets a model plan "
            "without ever seeing what it would be planning to ask about."
        ),
        mime_type="application/json",
    )
    def catalogue_resource() -> dict:
        return svc.catalogue_resource()

    return mcp


def main() -> None:  # pragma: no cover - exercised by examples/quickstart.py instead
    import anyio

    server = create_server()
    anyio.run(server.run_stdio_async)


if __name__ == "__main__":  # pragma: no cover
    main()
