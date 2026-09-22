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

Admission control note
-----------------------
This service currently enforces only a minimal, inline minimum-aggregate-
size rule (D1) directly -- the full D1-D5 policy ladder lives in
:mod:`tokenis.gateway.admission` (adopted from the P4 reproduction) and is
wired in once that module lands; until then, treat every method here as
demonstrating the *disclosure-boundary* architecture (typed returns, gated
Reveal, hash-chained audit trail) rather than as production-strength
admission control. This is called out again at the top of
:mod:`tokenis.gateway.admission` itself once it exists.

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
from typing import Any, Dict, List, Optional, Tuple

from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.crypto.ec_elgamal import Decryptor, KeyPair, keygen
from tokenis.gateway.compute import AggregateEngine, Predicate, average
from tokenis.gateway.reveal import RevealDenied, RevealObject, reveal
from tokenis.semantic.tokenizer import GeneralizationHierarchy, ScopedTokenizer


class AdmissionDenied(Exception):
    """Raised when a call fails the (currently minimal) admission check.
    See the module docstring: this stands in for
    :mod:`tokenis.gateway.admission` until that module is wired in."""


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

    def __post_init__(self) -> None:
        self._keypair: KeyPair = keygen()
        self._decryptor = Decryptor(self._keypair.private, max_value=10_000_000)
        self.tokenizer = ScopedTokenizer(key=self.tokenizer_key)
        self._scope = self.tokenizer.make_scope(tenant=self.tenant, epoch=self.epoch)
        self.engine = AggregateEngine(public_key=self._keypair.public)
        self.trace = DisclosureTrace()
        self._embeddings: Dict[str, Tuple[float, ...]] = {}
        self._token_by_name: Dict[str, str] = {}
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

    def _check_min_aggregate_size(self, predicate: Predicate, principal: str, purpose: str) -> int:
        count = self.engine.count(predicate)
        min_size = self.catalogue["revenue"].min_aggregate_size
        if count < min_size:
            self.trace.record_denial(
                AuditRecord(
                    principal=principal, obj_ref=predicate.name, purpose=purpose,
                    policy_version="v1", decision="deny",
                )
            )
            raise AdmissionDenied(
                f"minimum aggregate size not met ({count} < {min_size}) for {predicate.name!r}"
            )
        return count

    # -- tool 1: aggregate --------------------------------------------------

    def aggregate(
        self, principal: str, function: str, industry: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Dict[str, Any]:
        pred = self._predicate(industry, region)
        count = self._check_min_aggregate_size(pred, principal, "aggregate")
        total = self._decryptor.decrypt(self.engine.sum(pred))
        if function == "sum":
            value: Any = total
        elif function == "count":
            value = count
        elif function == "avg":
            value = average(total, count)
        else:
            raise ValueError(f"unsupported aggregate function {function!r}")
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=principal, obj_ref=pred.name, purpose="aggregate",
                policy_version="v1", decision="permit",
            ),
            value,
        )
        return {"function": function, "value": value, "matched_count": count}

    # -- tool 2: group_by -----------------------------------------------------

    def group_by(self, principal: str, key: str) -> Dict[str, Any]:
        if key not in ("industry", "region"):
            raise ValueError("group_by key must be an OPEN attribute: industry or region")
        keys = sorted({row[key] for row in self._all_public_rows() if key in row})
        groups: Dict[str, Any] = {}
        min_size = self.catalogue["revenue"].min_aggregate_size
        for k in keys:
            pred = self._predicate(**{key: k})  # type: ignore[arg-type]
            count = self.engine.count(pred)
            if count < min_size:
                groups[k] = {"suppressed": True, "reason": f"count {count} < minimum {min_size}"}
                self.trace.record_denial(
                    AuditRecord(
                        principal=principal, obj_ref=f"group_by:{key}={k}", purpose="group_by",
                        policy_version="v1", decision="deny",
                    )
                )
                continue
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
        pred = self._predicate(industry=industry)
        self._check_min_aggregate_size(pred, principal, "compare_periods")
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

    def exists(
        self, principal: str, industry: Optional[str] = None, customer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        pred = self._predicate(industry=industry)
        if customer_token is not None:
            base_matcher = pred.matcher
            pred = Predicate(
                pred.name + f",token={customer_token}",
                lambda row, base=base_matcher: base(row) and row.get("customer_token") == customer_token,
            )
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

    def disclose_ratio(
        self, principal: str, numerator_industry: str, denominator_industry: str, purpose: str,
    ) -> Dict[str, Any]:
        num_pred = self._predicate(industry=numerator_industry)
        den_pred = self._predicate(industry=denominator_industry)

        def policy(_principal: str, _obj: RevealObject, purpose: str) -> bool:
            return purpose.startswith("authorized_")

        def decrypt_fn(_obj: RevealObject) -> float:
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

    def disclose_bucket(
        self, principal: str, industry: str, thresholds: List[float], labels: List[str], purpose: str,
    ) -> Dict[str, Any]:
        if len(labels) != len(thresholds) + 1:
            raise ValueError("labels must have exactly one more entry than thresholds")
        pred = self._predicate(industry=industry)

        def policy(_principal: str, _obj: RevealObject, purpose: str) -> bool:
            return purpose.startswith("authorized_")

        def decrypt_fn(_obj: RevealObject) -> str:
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
    """Loads five small, entirely fictional rows -- used by
    :mod:`tokenis.mcp_server.server`'s default server, the conformance
    suite's fixtures, and ``examples/quickstart.py`` so all three exercise
    the same data without each hand-rolling it."""
    rows = [
        ("r1", {"industry": "finance", "region": "Seoul-Gangnam"}, 1_000_000, "Acme Corp", (1.0, 0.0, 0.0)),
        ("r2", {"industry": "finance", "region": "Busan-Haeundae"}, 2_000_000, "Beta LLC", (0.9, 0.1, 0.0)),
        ("r3", {"industry": "retail", "region": "Seoul-Gangnam"}, 500_000, "Gamma Inc", (0.0, 1.0, 0.0)),
        ("r4", {"industry": "retail", "region": "Seoul-Jongno"}, 750_000, "Delta Co", (0.0, 0.9, 0.1)),
        ("r5", {"industry": "finance", "region": "Seoul-Gangnam"}, 1_250_000, "Epsilon Ltd", (0.95, 0.05, 0.0)),
    ]
    for record_id, public_fields, revenue, name, embedding in rows:
        service.ingest(record_id, public_fields, revenue, customer_name=name, embedding=embedding)
