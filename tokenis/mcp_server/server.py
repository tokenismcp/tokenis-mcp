# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The Tokenis MCP server: exposes a
:class:`~tokenis.gateway.service.TokenisGatewayService` as MCP tools, a
catalogue resource and an analysis prompt, over the official ``mcp`` SDK.

Tool schemas are generated from the loaded dataset: column arguments are
enums of the real column names, filters are objects whose keys are the
filterable columns (and whose values, for open columns with a small domain,
are enums of the values present). A model therefore sees exactly the
vocabulary it may use (P2 §3.5), and malformed calls are rejected by schema
validation before any gateway code runs.

Identity
--------
Every tool resolves the caller with ``principal_resolver(ctx)``. The
principal never comes from a tool argument (P4 Theorem 13 / Corollary 14):

- stdio (one local user): :func:`fixed_principal` -- the OS account that
  launched the server *is* the caller.
- HTTP: :func:`tokenis.server_auth.authenticated_principal`, reading the
  subject of the bearer token the SDK's auth middleware already verified
  (pass the matching ``token_verifier`` and ``auth`` settings).

Responses
---------
Denials raise ``ToolError`` with one fixed message (``is_error=True`` on
the wire), so the model can tell a refusal from a result but not which rule
fired. Every call, successful or not, is padded to the declared latency
quantum (W6) with an async sleep, so padding costs no worker thread; the
gateway work itself runs on a bounded thread pool.
"""
from __future__ import annotations

import functools
import getpass
import inspect
import logging
import re
import time
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

import anyio
import anyio.to_thread
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, create_model
from typing_extensions import Annotated

from tokenis.gateway.latency import pad_to_granularity_async
from tokenis.gateway.service import AdmissionDenied, ArgumentError, TokenisGatewayService
from tokenis.server_auth import AuthenticationRequired, validate_principal

log = logging.getLogger("tokenis.server")

PrincipalResolver = Callable[[Context], str]
TaintResolver = Callable[[Context], int]

TOKEN_PATTERN = r"^[0-9a-f]{32}$"  # noqa: S105 -- the pseudonym format, not a credential

INSTRUCTIONS = """\
Tokenis answers questions about a confidential dataset without revealing \
individual records.

1. Call describe_dataset first: it lists the columns, the exact values you \
can filter on, the minimum group size k, your remaining query budget, and \
any disclosure purposes you may use.
2. Sealed columns can only be aggregated (sum, avg, count, and var where \
enabled) over groups of at least k records. Filter with open-column values \
exactly as listed, or with tokens returned by earlier results.
3. A denial is deliberate and never says which rule fired. Broaden the \
filters or ask a different question; do not retry near-identical narrow \
queries -- every admitted query uses budget, and queries that together \
would isolate a record are refused.
4. disclose_ratio and disclose_bucket cross the disclosure boundary and are \
audited. Use them only when the user's task matches one of the purposes \
listed by describe_dataset.
5. Never try to single out individual records or to reverse tokens. Report \
aggregates with their group sizes and units."""


def fixed_principal(principal: str) -> PrincipalResolver:
    """A resolver that always returns ``principal``: for stdio servers
    (one local user) and in-process embedding where the application has
    already authenticated its user."""
    validate_principal(principal)

    def resolve(_ctx: Context) -> str:
        return principal

    return resolve


def local_principal() -> str:
    """``local:<os-user>``, sanitised to the principal alphabet."""
    user = re.sub(r"[^A-Za-z0-9._@:+-]", "_", getpass.getuser() or "user")[:100]
    return f"local:{user}"


def header_taint(header: str, default: int = 0) -> TaintResolver:
    """Taint from an HTTP header set by the agent host (P4 Assumption 15:
    the host, not the model, knows when untrusted content entered the
    context). Values ``1``/``true``/``yes`` mean tainted. Absent header or
    stdio: ``default``."""
    wanted = header.lower()

    def resolve(ctx: Context) -> int:
        try:
            headers = ctx.headers
        except ValueError:
            headers = None
        if headers is None:
            return default
        value = next((v for k, v in headers.items() if k.lower() == wanted), None)
        if value is None:
            return default
        return 1 if value.strip().lower() in ("1", "true", "yes") else 0

    return resolve


def _described(annotation: Any, description: str, **constraints: Any) -> Any:
    return Annotated[annotation, Field(description=description, **constraints)]


def _literal(values: List[str]) -> Any:
    return Literal[tuple(values)]  # type: ignore[valid-type]


def _filters_model(svc: TokenisGatewayService, name: str) -> type:
    limit = svc.settings.disclosure.max_enum_values
    fields: Dict[str, Any] = {}
    for col in svc.schema.filterable:
        if col.protection == "open":
            domain = svc.domain(col.name)
            value_type: Any = _literal(domain) if 0 < len(domain) <= limit else str
            desc = col.description or col.name
        else:
            value_type = Annotated[str, StringConstraints(pattern=TOKEN_PATTERN)]
            desc = f"{col.description or col.name} (a token from an earlier result)"
        fields[col.name] = (Optional[value_type], Field(default=None, description=desc))
    model: type = create_model(name, __config__=ConfigDict(extra="forbid"), **fields)
    return model


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    return value


def _make_tool(name: str, params: List[Tuple[str, Any, Any]], run: Callable[..., Any]) -> Callable:
    async def tool(**kwargs: Any) -> Dict[str, Any]:
        ctx = kwargs.pop("ctx")
        result: Dict[str, Any] = await run(ctx, name, {k: _plain(v) for k, v in kwargs.items()})
        return result

    parameters = [inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context)]
    annotations: Dict[str, Any] = {"ctx": Context}
    for pname, annotation, default in params:
        parameters.append(
            inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, annotation=annotation, default=default)
        )
        annotations[pname] = annotation
    annotations["return"] = dict
    tool.__signature__ = inspect.Signature(parameters, return_annotation=dict)  # type: ignore[attr-defined]
    tool.__annotations__ = annotations
    tool.__name__ = name
    tool.__qualname__ = name
    return tool


_EMPTY = inspect.Parameter.empty


def create_server(
    service: TokenisGatewayService,
    *,
    principal_resolver: PrincipalResolver,
    taint_resolver: Optional[TaintResolver] = None,
    token_verifier: Optional[TokenVerifier] = None,
    auth: Optional[AuthSettings] = None,
    name: str = "tokenis",
    max_concurrency: int = 16,
) -> MCPServer:
    """An :class:`MCPServer` for ``service``. See the module docstring for
    how to choose ``principal_resolver``; ``token_verifier`` and ``auth``
    turn on the SDK's bearer-token middleware for the HTTP transport."""
    if (token_verifier is None) != (auth is None):
        raise ValueError("token_verifier and auth must be given together")
    service.seal()
    svc = service
    resolve_taint: TaintResolver = taint_resolver or (lambda _ctx: 0)
    limiter = anyio.CapacityLimiter(max_concurrency)
    granularity = svc.latency_granularity_ms

    mcp = MCPServer(
        name=name,
        title="Tokenis disclosure-boundary gateway",
        description="Aggregate questions over encrypted data, under admission control and audit.",
        instructions=INSTRUCTIONS,
        token_verifier=token_verifier,
        auth=auth,
    )

    async def run(ctx: Context, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()
        try:
            try:
                principal = principal_resolver(ctx)
                taint = resolve_taint(ctx)
            except AuthenticationRequired:
                raise ToolError("authentication required") from None
            call = functools.partial(svc.invoke, tool, principal, arguments, taint)
            return await anyio.to_thread.run_sync(call, limiter=limiter)
        except AdmissionDenied as exc:
            # The rule goes to the operator's log (and the trace), never to the caller.
            log.info("denied tool=%s rule=%s", tool, exc.rule)
            raise ToolError(str(exc)) from None
        except ArgumentError as exc:
            raise ToolError(f"invalid arguments: {exc}") from None
        finally:
            await pad_to_granularity_async(start, granularity)

    schema = svc.schema
    sealed = [c.name for c in schema.sealed]
    filterable = [c.name for c in schema.filterable]
    functions = ["sum", "avg", "count"] + (["var"] if any(c.allow_variance for c in schema.sealed) else [])
    read_only = ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=False, open_world_hint=False,
    )
    filters_t = _filters_model(svc, "Filters")
    sealed_t = _literal(sealed)
    k = svc.k

    def add(name: str, description: str, params: List[Tuple[str, Any, Any]], title: str) -> None:
        mcp.add_tool(
            _make_tool(name, params, run), name=name, title=title, description=description,
            annotations=read_only.model_copy(update={"title": title}),
        )

    filters_param = (
        "filters",
        _described(Optional[filters_t], "Only records matching ALL of these column values."),
        None,
    )

    add(
        "describe_dataset",
        "Describe the dataset: columns and their protection, the values you can filter on, "
        f"the minimum group size (k={k}), your remaining query budget, and the disclosure "
        "purposes you may use. Call this first. Uses no budget.",
        [],
        "Describe dataset",
    )
    add(
        "aggregate",
        f"Compute sum, avg or count (and var where enabled) of a sealed column over the records "
        f"matching the filters. Groups smaller than {k} records are refused. Returns the value "
        "and the number of matching records.",
        [
            ("function", _described(_literal(functions), "The aggregate to compute."), _EMPTY),
            ("column", _described(Optional[sealed_t], "Sealed column to aggregate (not needed for count)."), None),
            filters_param,
        ],
        "Aggregate",
    )
    add(
        "group_by",
        "Aggregate a sealed column separately for each value of a filterable column. Groups "
        f"with fewer than {k} records (or that the policy refuses) come back as suppressed.",
        [
            ("key", _described(_literal(filterable), "Column whose values define the groups."), _EMPTY),
            ("function", _described(_literal(["sum", "avg", "count"]), "Aggregate per group."), "sum"),
            ("column", _described(Optional[sealed_t], "Sealed column (not needed for count)."), None),
            filters_param,
        ],
        "Group by",
    )
    if "compare_periods" in svc.tool_names:
        add(
            "compare_periods",
            "Compare the totals of two sealed columns (e.g. two periods) over the same records. "
            "Returns only the direction (increase / decrease / flat within 2%) and a ratio band, "
            "never the values or their difference.",
            [
                ("column_a", _described(sealed_t, "Baseline column (e.g. the earlier period)."), _EMPTY),
                ("column_b", _described(sealed_t, "Column compared against the baseline."), _EMPTY),
                filters_param,
            ],
            "Compare periods",
        )
    if "similarity_search" in svc.tool_names:
        entity = schema.entity
        add(
            "similarity_search",
            f"Find the entities most similar to one given by its token ({entity.name if entity else ''}"
            "). Returns tokens with a coarse similarity level, never the underlying data.",
            [
                ("token", _described(
                    Annotated[str, StringConstraints(pattern=TOKEN_PATTERN)],
                    "Entity token from an earlier result."), _EMPTY),
                ("top_k", _described(
                    int, "How many results.", ge=1, le=svc.settings.disclosure.max_top_k), 3),
            ],
            "Similarity search",
        )
    add(
        "exists",
        f"Check whether at least {k} records match the filters. Answers false for fewer than "
        f"{k} matches, including zero: the gateway never distinguishes 0 from a handful.",
        [("filters", _described(filters_t, "Column values that must all match."), _EMPTY)],
        "Exists (at least k)",
    )
    if "disclose_ratio" in svc.tool_names:
        purposes_t = _described(
            _literal([p.name for p in svc.settings.purposes]),
            "Why this disclosure is needed; must be a purpose you are authorised for.",
        )
        add(
            "disclose_ratio",
            "DISCLOSURE (audited): the ratio of a sealed column's total over two groups, "
            "numerator / denominator. Each group must pass the same checks as aggregate. Use "
            "only for an authorised purpose.",
            [
                ("column", _described(sealed_t, "Sealed column to total."), _EMPTY),
                ("numerator_filters", _described(filters_t, "Numerator group."), _EMPTY),
                ("denominator_filters", _described(filters_t, "Denominator group."), _EMPTY),
                ("purpose", purposes_t, _EMPTY),
            ],
            "Disclose ratio",
        )
        limit = svc.settings.disclosure.max_buckets
        add(
            "disclose_bucket",
            "DISCLOSURE (audited): which named bucket a group's total falls into, given ascending "
            "thresholds (labels has one more entry than thresholds). Use only for an authorised "
            "purpose.",
            [
                ("column", _described(sealed_t, "Sealed column to total."), _EMPTY),
                ("thresholds", _described(
                    List[float], "Ascending bucket boundaries, in the column's units.",
                    min_length=1, max_length=limit - 1), _EMPTY),
                ("labels", _described(
                    List[Annotated[str, StringConstraints(min_length=1, max_length=64)]],
                    "Bucket names: one more than thresholds.", min_length=2, max_length=limit),
                 _EMPTY),
                ("purpose", purposes_t, _EMPTY),
                filters_param,
            ],
            "Disclose bucket",
        )

    @mcp.resource(
        "tokenis://catalogue",
        name="catalogue",
        description=(
            "Schema metadata only -- column names, protection classes, minimum group size, "
            "disclosure purposes. No row values."
        ),
        mime_type="application/json",
    )
    def catalogue_resource() -> dict:
        return svc.catalogue_resource()

    @mcp.prompt(
        name="analysis_guide",
        title="Analyse the Tokenis dataset",
        description="How to answer a question with Tokenis tools without over-querying.",
    )
    def analysis_guide(question: str = "") -> str:
        task = f"\n\nThe question to answer: {question}" if question else ""
        return INSTRUCTIONS + task

    return mcp
