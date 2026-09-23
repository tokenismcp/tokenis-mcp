# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""``TokenisGatewayService``: composes the semantic, compute, admission and
reveal modules into the seven-tool surface described in
``tokenis/spec/tool-surface.md`` (R2 §1.4). :mod:`tokenis.mcp_server.server`
wires this service's methods to actual MCP tool/resource declarations;
:mod:`tokenis.conformance.reference_gateway` uses a smaller, independent
three-tool harness for the W1-W6 suite rather than this class, so the two
can evolve without the conformance tests being coupled to every change here.

``principal`` is not authentication
------------------------------------
Every method below takes an explicit ``principal: str`` argument for
reference-implementation simplicity. **This is not how a real deployment
should determine who is calling.** P4's Theorem 13 / Corollary 14
(identity propagation is a precondition) is specifically about this: the
authenticated end-user subject must come from a source the caller cannot
forge -- an OIDC/SAML-verified session, not a plain string the model (or
content that has steered the model, per P4's injection adversary) can set
to anything it likes. A production integration must bind ``principal`` to
:mod:`mcp`'s own authenticated request context (see the
``token_verifier``/``auth`` parameters `MCPServer` accepts) before this
service ever sees it, not trust a tool argument.

Admission control
------------------
Every value-bearing call (``aggregate``, ``group_by``, ``compare_periods``,
and the two underlying sums inside ``disclose_ratio``/``disclose_bucket``)
is checked against a real :class:`~tokenis.gateway.admission.AdmissionPolicy`
(the full D1-D5 ladder) before it executes -- not a stand-in. ``exists`` is
checked too, as a ``COUNT`` query (exempt from D2's rowspace audit, since a
set size is public, but still subject to D1/D3/D4/D5). The admission
policy is rebuilt from the current ledger the first time it's needed and
whenever the record count changes; since every service in this repository
loads its ledger once via :func:`load_demo_ledger` before any tool call,
this means one build per service instance in practice -- interleaving
``ingest`` calls with tool calls would reset the D2 audit history and D3
budget state, which is a documented reference-implementation limitation,
not a silent correctness gap (see :meth:`_ensure_admission`).

``credential_id`` is set equal to ``principal`` throughout this service --
another reference simplification. A real deployment has short-lived
per-session credentials distinct from the long-lived authenticated subject;
collapsing the two here means this service's own code path never exercises
:class:`~tokenis.gateway.admission.CredentialScopedBudget`'s failure mode
(it isn't used -- :class:`~tokenis.gateway.admission.SubjectScopedBudget`
is the only budget scope this service constructs), so nothing is silently
weakened by the collapse.

Similarity search simplification
---------------------------------
"Encrypted vectors" (R2's phrase for the ``similarity_search`` tool) would
need a vector-similarity-preserving encryption scheme this reference
crypto module does not implement. Standing in for it: embeddings are held
in plaintext only inside this trusted service process (the same trust
boundary :meth:`ingest` already relies on for ingesting sealed values --
see :mod:`tokenis.gateway.compute`), and only ranked TOKEN-class IDs plus a
banded similarity score ever leave it. The disclosure-boundary property the
real tool is meant to have (no raw vector, no raw identifier crosses) is
satisfied by the *return-form typing*, independent of which underlying
similarity computation produced it.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.crypto.ec_fhe import Decryptor, KeyPair, keygen
from tokenis.gateway.admission import (
    AdmissionPolicy,
    And,
    Eq,
    MissingSubjectIdError,
)
from tokenis.gateway.admission import All as AdmitAll
from tokenis.gateway.admission import Query as AdmQuery
from tokenis.gateway.admission import QueryContext as AdmQueryContext
from tokenis.gateway.compute import AggregateEngine, Predicate, average
from tokenis.gateway.latency import quantize_latency
from tokenis.gateway.reveal import RevealDenied, RevealObject, reveal
from tokenis.semantic.tokenizer import GeneralizationHierarchy, ScopedTokenizer


class AdmissionDenied(Exception):
    """Raised when a call is refused by :class:`~tokenis.gateway.admission.AdmissionPolicy`
    (or by its ``MissingSubjectIdError`` precondition -- see Corollary 14)."""


@dataclass
class CatalogueEntry:
    protection_class: str  # "open" | "token" | "sealed"
    min_aggregate_size: int = 1
    description: str = ""


@dataclass
class TokenisGatewayService:
    """The product-shaped gateway: seven tools + catalogue resource over a
    loaded ledger. See the module docstring for what is and isn't wired up
    yet.
    """

    tenant: str = "demo"
    epoch: int = 1
    tokenizer_key: bytes = b"tokenis-demo-tenant-key-32-bytes"
    catalogue: Dict[str, CatalogueEntry] = field(default_factory=dict)
    #: W6 (P2 Definition 17): every value-bearing tool method is padded to
    #: the next multiple of this many milliseconds, on both the success and
    #: the exception path -- see tokenis/gateway/latency.py. 250ms sits
    #: inside R2's tightest quoted SLO bucket (in-call conversational use,
    #: p95 <= 200ms for Tokenis's own added latency) with headroom for the
    #: model host's own latency on top; tune per deployment.
    latency_granularity_ms: float = 250.0

    def __post_init__(self) -> None:
        self._keypair: KeyPair = keygen()
        self._decryptor = Decryptor(self._keypair.private)
        self.tokenizer = ScopedTokenizer(key=self.tokenizer_key)
        self._scope = self.tokenizer.make_scope(tenant=self.tenant, epoch=self.epoch)
        self.engine = AggregateEngine(public_key=self._keypair.public)
        self.trace = DisclosureTrace()
        self._embeddings: Dict[str, Tuple[float, ...]] = {}
        self._token_by_name: Dict[str, str] = {}
        self._industry_values: List[str] = []
        self._region_values: List[str] = []
        self._customer_token_values: List[str] = []
        self._admission: Optional[AdmissionPolicy] = None
        if not self.catalogue:
            self.catalogue = {
                "revenue": CatalogueEntry("sealed", min_aggregate_size=3, description="Annual revenue"),
                "industry": CatalogueEntry("open", description="Industry sector"),
                "region": CatalogueEntry("open", description="Registered region"),
                "customer_name": CatalogueEntry("token", description="Customer legal name"),
            }
        self.generalization = GeneralizationHierarchy(
            {"region": [lambda v: v.split("-")[0]]}
        )

    # -- ingest -----------------------------------------------------------

    def ingest(
        self,
        record_id: str,
        public_fields: Dict[str, Any],
        sealed_revenue: int,
        customer_name: Optional[str] = None,
        embedding: Optional[Tuple[float, ...]] = None,
    ) -> None:
        fields = dict(public_fields)
        if customer_name is not None:
            token = self.tokenizer.tokenize("customer_name", self._scope, customer_name)
            fields["customer_token"] = token
            self._token_by_name[customer_name] = token
        self.engine.ingest(record_id, fields, sealed_revenue, with_square=True)
        self._industry_values.append(str(fields.get("industry", "")))
        self._region_values.append(str(fields.get("region", "")))
        self._customer_token_values.append(str(fields.get("customer_token", "")))
        if embedding is not None:
            token = fields.get("customer_token", record_id)
            self._embeddings[token] = tuple(embedding)

    # -- shared helpers -----------------------------------------------------

    def _predicate(self, industry: Optional[str] = None, region: Optional[str] = None) -> Predicate:
        def matcher(row: Dict[str, Any]) -> bool:
            if industry is not None and row.get("industry") != industry:
                return False
            return not (region is not None and row.get("region") != region)

        name = f"industry={industry},region={region}"
        return Predicate(name, matcher)

    def _ensure_admission(self) -> None:
        """(Re)build the AdmissionPolicy from the current ledger if it's
        stale or hasn't been built yet. See the module docstring for why
        rebuilding resets D2/D3 state, and why that's a documented
        limitation rather than a silent one."""
        n = len(self.engine)
        if self._admission is not None and self._admission.n == n:
            return
        sealed_columns = frozenset(
            name for name, entry in self.catalogue.items() if entry.protection_class == "sealed"
        )
        self._admission = AdmissionPolicy(
            n=n,
            public_attributes={
                "industry": np.array(self._industry_values, dtype=object),
                "region": np.array(self._region_values, dtype=object),
                "customer_token": np.array(self._customer_token_values, dtype=object),
            },
            catalogue=sealed_columns,
            k=self.catalogue["revenue"].min_aggregate_size,
            budget=1000,
            taint_budget=100,
            taint_call_cap=200,
        )

    def _admission_predicate(
        self,
        industry: Optional[str] = None,
        region: Optional[str] = None,
        customer_token: Optional[str] = None,
    ):
        parts = []
        if industry is not None:
            parts.append(Eq("industry", industry))
        if region is not None:
            parts.append(Eq("region", region))
        if customer_token is not None:
            parts.append(Eq("customer_token", customer_token))
        if not parts:
            return AdmitAll()
        if len(parts) == 1:
            return parts[0]
        return And(*parts)

    def _check_admission(
        self,
        principal: str,
        function: str,
        industry: Optional[str] = None,
        region: Optional[str] = None,
        customer_token: Optional[str] = None,
        column: Optional[str] = "revenue",
        purpose: str = "aggregate",
    ) -> int:
        """Runs the query through the full D1-D5 :class:`AdmissionPolicy`
        before any ciphertext is touched. Raises :class:`AdmissionDenied`
        (after logging the denial to the trace, per P2 Remark 18) if
        refused; otherwise returns the query's matched count."""
        self._ensure_admission()
        assert self._admission is not None  # for type-checkers; set by _ensure_admission
        predicate = self._admission_predicate(industry, region, customer_token)
        query = AdmQuery(predicate=predicate, function=function, column=column)
        context = AdmQueryContext(subject_id=principal, credential_id=principal, taint=0)
        ref = f"industry={industry},region={region},function={function}"
        try:
            decision = self._admission.decide(query, context)
        except MissingSubjectIdError as exc:
            self.trace.record_denial(
                AuditRecord(
                    principal=principal or "", obj_ref=ref, purpose=purpose,
                    policy_version="v1", decision="deny",
                )
            )
            raise AdmissionDenied(str(exc)) from exc
        if not decision.admitted:
            self.trace.record_denial(
                AuditRecord(
                    principal=principal, obj_ref=ref, purpose=purpose,
                    policy_version="v1", decision="deny",
                )
            )
            raise AdmissionDenied(
                f"{decision.rule}: {decision.reason}"
                + (f" (matched {decision.set_size})" if decision.set_size is not None else "")
            )
        if decision.set_size is not None:
            return decision.set_size
        return self.engine.count(self._predicate(industry, region))

    # -- tool 1: aggregate --------------------------------------------------

    @quantize_latency
    def aggregate(
        self, principal: str, function: str, industry: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Dict[str, Any]:
        adm_function = {"sum": "SUM", "count": "COUNT", "avg": "AVG"}.get(function)
        if adm_function is None:
            raise ValueError(f"unsupported aggregate function {function!r}")
        column = None if adm_function == "COUNT" else "revenue"
        count = self._check_admission(
            principal, adm_function, industry=industry, region=region, column=column,
            purpose="aggregate",
        )
        pred = self._predicate(industry, region)
        if function == "count":
            value: Any = count
        else:
            total = self._decryptor.decrypt(self.engine.sum(pred))
            value = total if function == "sum" else average(total, count)
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=principal, obj_ref=pred.name, purpose="aggregate",
                policy_version="v1", decision="permit",
            ),
            value,
        )
        return {"function": function, "value": value, "matched_count": count}

    # -- tool 2: group_by -----------------------------------------------------

    @quantize_latency
    def group_by(self, principal: str, key: str) -> Dict[str, Any]:
        if key not in ("industry", "region"):
            raise ValueError("group_by key must be an OPEN attribute: industry or region")
        keys = sorted({row[key] for row in self._all_public_rows() if key in row})
        groups: Dict[str, Any] = {}
        for k in keys:
            kwargs = {key: k}
            try:
                count = self._check_admission(
                    principal, "SUM", column="revenue", purpose="group_by", **kwargs,
                )
            except AdmissionDenied as exc:
                groups[k] = {"suppressed": True, "reason": str(exc)}
                continue
            pred = self._predicate(**kwargs)  # type: ignore[arg-type]
            total = self._decryptor.decrypt(self.engine.sum(pred))
            band = _band(total)
            groups[k] = {"suppressed": False, "band": band, "count": count}
            self.trace.record_aggregate_result(
                AuditRecord(
                    principal=principal, obj_ref=f"group_by:{key}={k}", purpose="group_by",
                    policy_version="v1", decision="permit",
                ),
                band,
            )
        return {"key": key, "groups": groups}

    def _all_public_rows(self) -> List[Dict[str, Any]]:
        # Reference-implementation convenience: AggregateEngine doesn't
        # expose a bulk iterator, so reconstruct via matching_ids against
        # an always-true predicate.
        always = Predicate("all", lambda _row: True)
        return [self.engine.public_fields_of(rid) for rid in self.engine.matching_ids(always)]

    # -- tool 3: compare_periods ---------------------------------------------

    @quantize_latency
    def compare_periods(
        self, principal: str, industry: str, period_a_multiplier: float, period_b_multiplier: float,
    ) -> Dict[str, Any]:
        """Reference simplification: this demo ledger has one period, so
        "period A" / "period B" are simulated by scaling the same sealed
        total by publicly-known multipliers (e.g. a disclosed YoY growth
        factor from an external source) -- a real deployment would hold
        genuinely separate encrypted period columns. Only a coarse
        direction/ratio crosses the boundary, never the raw values or
        their raw difference (see ``tokenis/spec/tool-surface.md``)."""
        self._check_admission(
            principal, "SUM", industry=industry, column="revenue", purpose="compare_periods",
        )
        pred = self._predicate(industry=industry)
        total = self._decryptor.decrypt(self.engine.sum(pred))
        a = total * period_a_multiplier
        b = total * period_b_multiplier
        if a == 0:
            raise ValueError("period A total is zero; comparison undefined")
        ratio = b / a
        direction = "increase" if ratio > 1.02 else "decrease" if ratio < 0.98 else "flat"
        result = {"direction": direction, "ratio_band": _band_ratio(ratio)}
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=principal, obj_ref=pred.name, purpose="compare_periods",
                policy_version="v1", decision="permit",
            ),
            result,
        )
        return result

    # -- tool 4: similarity_search --------------------------------------------

    @quantize_latency
    def similarity_search(self, principal: str, query_token: str, top_k: int = 3) -> Dict[str, Any]:
        if query_token not in self._embeddings:
            raise ValueError("unknown query_token (no embedding on file)")
        query = self._embeddings[query_token]
        scored = []
        for token, vec in self._embeddings.items():
            if token == query_token:
                continue
            scored.append((token, _cosine_similarity(query, vec)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        top = [{"token": t, "similarity_band": _band_ratio(s)} for t, s in scored[:top_k]]
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=principal, obj_ref=f"similarity_search:{query_token}",
                purpose="similarity_search", policy_version="v1", decision="permit",
            ),
            top,
        )
        return {"query_token": query_token, "results": top}

    # -- tool 5: exists ------------------------------------------------------

    @quantize_latency
    def exists(
        self, principal: str, industry: Optional[str] = None, customer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._check_admission(
            principal, "COUNT", industry=industry, customer_token=customer_token, purpose="exists",
        )
        pred = self._predicate(industry=industry)
        if customer_token is not None:
            base_matcher = pred.matcher

            def matcher(
                row: Dict[str, object], base: Callable[[Dict[str, object]], bool] = base_matcher
            ) -> bool:
                return base(row) and row.get("customer_token") == customer_token

            pred = Predicate(pred.name + f",token={customer_token}", matcher)
        found = self.engine.count(pred) > 0
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=principal, obj_ref=pred.name, purpose="exists",
                policy_version="v1", decision="permit",
            ),
            found,
        )
        return {"exists": found}

    # -- tool 6: disclose_ratio ------------------------------------------------

    @quantize_latency
    def disclose_ratio(
        self, principal: str, numerator_industry: str, denominator_industry: str, purpose: str,
    ) -> Dict[str, Any]:
        num_pred = self._predicate(industry=numerator_industry)
        den_pred = self._predicate(industry=denominator_industry)

        def policy(_principal: str, _obj: RevealObject, purpose: str) -> bool:
            return purpose.startswith("authorized_")

        def decrypt_fn(_obj: RevealObject) -> float:
            # Both underlying sums go through the same D1-D5 AdmissionPolicy
            # any other SUM query would (raises AdmissionDenied, which
            # RevealDenied does not subclass -- see the try/except below).
            self._check_admission(
                principal, "SUM", industry=numerator_industry, column="revenue",
                purpose="disclose_ratio.numerator",
            )
            self._check_admission(
                principal, "SUM", industry=denominator_industry, column="revenue",
                purpose="disclose_ratio.denominator",
            )
            num = self._decryptor.decrypt(self.engine.sum(num_pred))
            den = self._decryptor.decrypt(self.engine.sum(den_pred))
            if den == 0:
                raise ZeroDivisionError("denominator aggregate is zero")
            return num / den

        obj = RevealObject(ref=f"ratio:{num_pred.name}/{den_pred.name}", kind="aggregate")
        try:
            value = reveal(principal, obj, purpose, "v1", policy, decrypt_fn, self.trace)
        except RevealDenied as exc:
            raise AdmissionDenied(str(exc)) from exc
        return {"ratio": value}

    # -- tool 7: disclose_bucket -----------------------------------------------

    @quantize_latency
    def disclose_bucket(
        self, principal: str, industry: str, thresholds: List[float], labels: List[str], purpose: str,
    ) -> Dict[str, Any]:
        if len(labels) != len(thresholds) + 1:
            raise ValueError("labels must have exactly one more entry than thresholds")
        pred = self._predicate(industry=industry)

        def policy(_principal: str, _obj: RevealObject, purpose: str) -> bool:
            return purpose.startswith("authorized_")

        def decrypt_fn(_obj: RevealObject) -> str:
            self._check_admission(
                principal, "SUM", industry=industry, column="revenue",
                purpose="disclose_bucket",
            )
            total = self._decryptor.decrypt(self.engine.sum(pred))
            for threshold, label in zip(thresholds, labels):
                if total < threshold:
                    return label
            return labels[-1]

        obj = RevealObject(ref=f"bucket:{pred.name}", kind="aggregate")
        try:
            label = reveal(principal, obj, purpose, "v1", policy, decrypt_fn, self.trace)
        except RevealDenied as exc:
            raise AdmissionDenied(str(exc)) from exc
        return {"bucket": label}

    # -- resource: catalogue --------------------------------------------------

    def catalogue_resource(self) -> Dict[str, Any]:
        return {
            attribute: {
                "protection_class": entry.protection_class,
                "min_aggregate_size": entry.min_aggregate_size,
                "description": entry.description,
            }
            for attribute, entry in self.catalogue.items()
        }


def _band(value: int) -> str:
    """A coarse, order-of-magnitude band -- placeholder for the real
    product-mode-dependent banding described in ``reports/SUMMARY.md`` /
    the P3 disclosure-budget product modes."""
    if value <= 0:
        return "<=0"
    magnitude = int(math.log10(abs(value)))
    lower = 10**magnitude
    upper = 10 ** (magnitude + 1)
    return f"[{lower:,}-{upper:,})"


def _band_ratio(ratio: float) -> str:
    buckets = [0.5, 0.8, 0.95, 1.05, 1.2, 2.0]
    labels = ["<0.5x", "0.5-0.8x", "0.8-0.95x", "0.95-1.05x", "1.05-1.2x", "1.2-2x", ">2x"]
    for boundary, label in zip(buckets, labels):
        if ratio < boundary:
            return label
    return labels[-1]


def _cosine_similarity(a: Tuple[float, ...], b: Tuple[float, ...]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def load_demo_ledger(service: TokenisGatewayService) -> None:
    """Loads eight small, entirely fictional rows -- used by
    :mod:`tokenis.mcp_server.server`'s default server, the conformance
    suite's fixtures, and ``examples/quickstart.py`` so all three exercise
    the same data without each hand-rolling it.

    Three industries, deliberately sized so both "denied" and "admitted"
    paths are reachable through every tool: ``finance`` and ``tech`` each
    have 3 rows (meeting the demo catalogue's minimum aggregate size of 3),
    while ``retail`` has only 2 (illustrating D1's minimum-aggregate-size
    denial, including through ``disclose_ratio``'s underlying sums, which
    are admission-checked exactly like a bare ``aggregate`` call).
    """
    rows = [
        ("r1", {"industry": "finance", "region": "Seoul-Gangnam"}, 1_000_000, "Acme Corp", (1.0, 0.0, 0.0)),
        ("r2", {"industry": "finance", "region": "Busan-Haeundae"}, 2_000_000, "Beta LLC", (0.9, 0.1, 0.0)),
        ("r3", {"industry": "retail", "region": "Seoul-Gangnam"}, 500_000, "Gamma Inc", (0.0, 1.0, 0.0)),
        ("r4", {"industry": "retail", "region": "Seoul-Jongno"}, 750_000, "Delta Co", (0.0, 0.9, 0.1)),
        ("r5", {"industry": "finance", "region": "Seoul-Gangnam"}, 1_250_000, "Epsilon Ltd", (0.95, 0.05, 0.0)),
        ("r6", {"industry": "tech", "region": "Seoul-Gangnam"}, 3_000_000, "Zeta AI", (0.0, 0.0, 1.0)),
        ("r7", {"industry": "tech", "region": "Seoul-Jongno"}, 1_500_000, "Eta Systems", (0.05, 0.0, 0.95)),
        ("r8", {"industry": "tech", "region": "Busan-Haeundae"}, 2_500_000, "Theta Labs", (0.0, 0.05, 0.95)),
    ]
    for record_id, public_fields, revenue, name, embedding in rows:
        service.ingest(record_id, public_fields, revenue, customer_name=name, embedding=embedding)
