# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""A small harness wiring the reference SDK's modules together, used only
by the conformance suite (not a fourth "real" gateway implementation --
:mod:`tokenis.mcp_server.server` is that; this harness exists so the W1-W6
tests can drive tool calls without needing a running MCP transport).

A third party implementing the Tokenis spec independently and wanting to
reuse `tokenis/conformance` should provide an object with the same
surface: a `call_tool(name, args, principal) -> ToolCallResult` method, a
`.trace` (a :class:`~tokenis.audit.trace.DisclosureTrace` or object with
the same shape), and a `.tokenizer` exposing `.tokenize`/`.make_scope`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.crypto.ec_fhe import Decryptor, keygen
from tokenis.gateway.compute import AggregateEngine, Predicate
from tokenis.gateway.reveal import RevealObject, reveal
from tokenis.semantic.tokenizer import ScopedTokenizer


class AggregateDenied(Exception):
    """Raised when an ``aggregate`` call is refused by a (minimal, D1-only)
    admission check -- distinct from :class:`~tokenis.gateway.reveal.RevealDenied`,
    which is specific to the Reveal operation (P2 Definition 15). The full
    D1-D5 admission ladder lives in :mod:`tokenis.gateway.admission`; this
    harness only reproduces the minimum-aggregate-size rule (D1) inline,
    since it exists to exercise W1-W4/W6, not to be the admission
    conformance target (see ``test_w5_simulatable_admission.py``, which
    tests :mod:`tokenis.gateway.admission` directly).
    """


@dataclass
class ToolCallResult:
    tool: str
    value: Any
    protection_class: str  # "open" | "token" | "sealed_aggregate" | "revealed"
    crossed_boundary: bool


class ReferenceGateway:
    """Wires crypto + tokenizer + compute + reveal + audit trace into
    something the conformance suite can call tools against. Loads a small
    fixed demo ledger; not connected to :mod:`tokenis.gateway.admission`
    yet (see ``test_w5_simulatable_admission.py`` for why that test is
    written separately against the admission module directly rather than
    through this harness).
    """

    def __init__(self, seed_key: bytes = b"conformance-suite-demo-key-32by"):
        self._keypair = keygen()
        self._decryptor = Decryptor(self._keypair.private)
        self.tokenizer = ScopedTokenizer(key=seed_key)
        self.engine = AggregateEngine(public_key=self._keypair.public)
        self.trace = DisclosureTrace()
        self._catalogue: Dict[str, Dict[str, Any]] = {
            "revenue": {"protection_class": "sealed", "min_aggregate_size": 3},
            "industry": {"protection_class": "open"},
            "customer_name": {"protection_class": "token"},
        }
        self._scope = self.tokenizer.make_scope(tenant="demo", epoch=1)
        self._load_demo_ledger()

    def _load_demo_ledger(self) -> None:
        demo_rows = [
            ("r1", "finance", "Acme Corp", 1_000_000),
            ("r2", "finance", "Beta LLC", 2_000_000),
            ("r3", "retail", "Gamma Inc", 500_000),
            ("r4", "retail", "Delta Co", 750_000),
            ("r5", "finance", "Epsilon Ltd", 1_250_000),
        ]
        for rid, industry, name, revenue in demo_rows:
            token = self.tokenizer.tokenize("customer_name", self._scope, name)
            self.engine.ingest(
                rid, {"industry": industry, "customer_token": token}, revenue
            )

    def catalogue(self) -> Dict[str, Dict[str, Any]]:
        """W5/D5-relevant: the public catalogue -- classified columns
        only, no row values."""
        return dict(self._catalogue)

    def call_tool(self, name: str, args: Dict[str, Any], principal: str) -> ToolCallResult:
        if name == "aggregate":
            return self._aggregate(args, principal)
        if name == "disclose_ratio":
            return self._disclose_ratio(args, principal)
        if name == "lookup_public":
            return self._lookup_public(args)
        raise ValueError(f"unknown tool {name!r}")

    def _predicate(self, args: Dict[str, Any]) -> Predicate:
        industry = args.get("industry")

        def matcher(row: Dict[str, Any], industry: Any = industry) -> bool:
            return bool(row["industry"] == industry)

        return Predicate(f"industry={industry}", matcher)

    def _aggregate(self, args: Dict[str, Any], principal: str) -> ToolCallResult:
        pred = self._predicate(args)
        count = self.engine.count(pred)
        if count < self._catalogue["revenue"]["min_aggregate_size"]:
            audit = AuditRecord(
                principal=principal,
                obj_ref=pred.name,
                purpose="aggregate",
                policy_version="v1",
                decision="deny",
            )
            self.trace.record_denial(audit)
            raise AggregateDenied(
                f"minimum aggregate size not met ({count} < "
                f"{self._catalogue['revenue']['min_aggregate_size']})"
            )
        total_ct = self.engine.sum(pred)
        plaintext = self._decryptor.decrypt(total_ct)
        audit = AuditRecord(
            principal=principal,
            obj_ref=pred.name,
            purpose="aggregate",
            policy_version="v1",
            decision="permit",
        )
        self.trace.record_aggregate_result(audit, plaintext)
        return ToolCallResult(
            tool="aggregate", value=plaintext, protection_class="sealed_aggregate",
            crossed_boundary=True,
        )

    def _disclose_ratio(self, args: Dict[str, Any], principal: str) -> ToolCallResult:
        numerator_pred = self._predicate({"industry": args["numerator_industry"]})
        denominator_pred = self._predicate({"industry": args["denominator_industry"]})

        def policy(principal: str, obj: RevealObject, purpose: str) -> bool:
            return purpose == "authorized_ratio_request"

        def decrypt_fn(obj: RevealObject) -> float:
            num = self._decryptor.decrypt(self.engine.sum(numerator_pred))
            den = self._decryptor.decrypt(self.engine.sum(denominator_pred))
            return num / den

        obj = RevealObject(ref=f"ratio:{numerator_pred.name}/{denominator_pred.name}", kind="aggregate")
        value = reveal(
            principal, obj, args.get("purpose", "authorized_ratio_request"), "v1",
            policy, decrypt_fn, self.trace,
        )
        return ToolCallResult(
            tool="disclose_ratio", value=value, protection_class="revealed", crossed_boundary=True
        )

    def _lookup_public(self, args: Dict[str, Any]) -> ToolCallResult:
        record_id = args["record_id"]
        fields = self.engine.public_fields_of(record_id)
        return ToolCallResult(
            tool="lookup_public", value=fields, protection_class="open", crossed_boundary=False
        )
