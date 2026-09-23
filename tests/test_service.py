# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The gateway service: tool semantics, generic denials, D4 taint, and the
concurrency guarantees the admission policy depends on."""
import threading
import time
from dataclasses import replace

import pytest

from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.gateway.admission import AdmissionPolicy
from tokenis.gateway.demo import DEMO_SETTINGS, demo_service
from tokenis.gateway.schema import (
    AdmissionSettings,
    ColumnSpec,
    DecryptionSettings,
    DisclosureSettings,
    GatewaySettings,
    RevealPurpose,
    Schema,
)
from tokenis.gateway.service import (
    DENIED_MESSAGE,
    AdmissionDenied,
    ArgumentError,
    TokenisGatewayService,
    band,
)

KEY = b"k" * 32
FAST = DisclosureSettings(latency_granularity_ms=1.0)
SMALL = DecryptionSettings(max_value=1 << 24, table_size=None)


@pytest.fixture
def svc():
    return demo_service(latency_granularity_ms=1.0)


def token_of(service, name):
    return service._tokenizer.tokenize("customer_name", service._scope, name)


# -- results ------------------------------------------------------------------------


def test_aggregate_functions(svc):
    finance = {"industry": "finance"}
    assert svc.aggregate("a", "sum", "revenue_2025", finance)["value"] == 4_250_000
    avg = svc.aggregate("a", "avg", "revenue_2024", {"industry": "tech"})
    assert avg["value"] == pytest.approx((2_000_000 + 1_200_000 + 1_900_000) / 3)
    count = svc.aggregate("a", "count", filters={"region": "Seoul-Gangnam"})
    assert count["value"] == count["matched_records"] == 4


def test_group_by_suppresses_small_groups(svc):
    out = svc.group_by("a", "industry", "sum", "revenue_2024")
    groups = {g["group"]: g for g in out["groups"]}
    assert groups["retail"] == {"group": "retail", "suppressed": True}
    assert groups["finance"]["value"] == 4_000_000
    assert groups["tech"]["matched_records"] == 3


def test_compare_periods_returns_direction_only(svc):
    out = svc.compare_periods("a", "revenue_2024", "revenue_2025", {"industry": "tech"})
    assert out["direction"] == "increase"
    assert out["ratio_band"] == "1.2-2x"  # 7.0M / 5.1M
    assert "value" not in out


def test_exists_never_distinguishes_zero_from_a_few(svc):
    # A token filter matches at most one record: the answer must be the
    # same whether that record is in the group or not, or exists() would
    # reveal each customer's attributes.
    acme = token_of(svc, "Acme Corp")  # a finance customer
    inside = svc.exists("a", {"customer_name": acme, "industry": "finance"})
    outside = svc.exists("a", {"customer_name": acme, "industry": "tech"})
    assert inside["at_least_k_records"] is outside["at_least_k_records"] is False
    assert svc.exists("a", {"industry": "tech"})["at_least_k_records"] is True
    assert svc.exists("a", {"industry": "retail"})["at_least_k_records"] is False


def test_similarity_search_returns_tokens_only(svc):
    acme = token_of(svc, "Acme Corp")
    out = svc.similarity_search("a", acme, top_k=2)
    assert [r["token"] for r in out["results"]] == [
        token_of(svc, "Epsilon Ltd"), token_of(svc, "Beta LLC"),
    ]
    assert {r["similarity"] for r in out["results"]} <= {"low", "medium", "high", "very high"}
    with pytest.raises(ArgumentError):
        svc.similarity_search("a", acme, top_k=DEMO_SETTINGS.disclosure.max_top_k + 1)
    with pytest.raises(AdmissionDenied):
        svc.similarity_search("a", "0" * 32)


def test_reveal_tools_need_an_authorised_purpose():
    settings = replace(
        DEMO_SETTINGS,
        purposes=(RevealPurpose("board", "Board pack", principals=("alice",)),),
        disclosure=FAST,
    )
    svc = demo_service(settings)
    args = {"column": "revenue_2025", "numerator_filters": {"industry": "finance"},
            "denominator_filters": {"industry": "tech"}}
    assert svc.disclose_ratio("alice", purpose="board", **args)["ratio"] == pytest.approx(4.25 / 7)
    with pytest.raises(AdmissionDenied) as denied:
        svc.disclose_ratio("bob", purpose="board", **args)
    assert denied.value.rule == "purpose-not-authorised"
    with pytest.raises(ArgumentError, match="purpose must be one of"):
        svc.disclose_ratio("alice", purpose="curiosity", **args)
    # An authorised purpose does not bypass admission of the underlying sums.
    with pytest.raises(AdmissionDenied) as denied:
        svc.disclose_ratio("alice", purpose="board", column="revenue_2025",
                           numerator_filters={"industry": "retail"},
                           denominator_filters={"industry": "tech"})
    assert denied.value.rule == "D1"
    bucket = svc.disclose_bucket("alice", "revenue_2025", [5e6, 8e6], ["s", "m", "l"], "board",
                                 {"industry": "tech"})
    assert bucket["bucket"] == "m"


def test_disclose_bucket_arguments_are_bounded(svc):
    with pytest.raises(ArgumentError, match="increasing"):
        svc.disclose_bucket("a", "revenue_2025", [5, 1], ["x", "y", "z"], "demo_review")
    with pytest.raises(ArgumentError):
        svc.disclose_bucket("a", "revenue_2025", [float("nan")], ["x", "y"], "demo_review")
    with pytest.raises(ArgumentError):
        svc.disclose_bucket("a", "revenue_2025", list(range(20)), ["x"] * 21, "demo_review")


# -- denials ----------------------------------------------------------------------


def test_every_denial_has_the_same_message_and_the_rule_is_traced(svc):
    rules = []
    for call in (
        lambda: svc.aggregate("a", "sum", "revenue_2025", {"industry": "retail"}),  # D1
        lambda: svc.aggregate("", "sum", "revenue_2025", {"industry": "tech"}),  # no subject
    ):
        with pytest.raises(AdmissionDenied) as exc:
            call()
        assert str(exc.value) == DENIED_MESSAGE
        assert "matched" not in str(exc.value)
        rules.append(exc.value.rule)
    assert rules == ["D1", "no-subject"]
    denials = [e for e in svc.trace if e.kind == "denial"]
    assert [e.audit.detail for e in denials] == rules


def test_differencing_is_refused():
    """sum(tech) - sum(tech, gangnam) isolates the one tech/jongno record:
    each query is admissible alone, the second must be refused (D2)."""
    svc = _race_ledger(seal=False)
    call = {"function": "sum", "column": "revenue"}
    svc.invoke("aggregate", "a", {**call, "filters": {"industry": "tech"}})
    with pytest.raises(AdmissionDenied) as exc:
        svc.invoke("aggregate", "a", {**call, "filters": {"industry": "tech", "region": "gangnam"}})
    assert exc.value.rule == "D2"
    # The same history applies to AVG (it implies the SUM once the set size is public).
    with pytest.raises(AdmissionDenied):
        svc.invoke("aggregate", "a", {**call, "function": "avg",
                                      "filters": {"industry": "tech", "region": "gangnam"}})


def test_budget_is_enforced_per_principal():
    settings = replace(DEMO_SETTINGS, disclosure=FAST,
                       admission=replace(DEMO_SETTINGS.admission, budget=2))
    svc = demo_service(settings)
    for _ in range(2):
        svc.aggregate("a", "count", filters={"industry": "tech"})
    with pytest.raises(AdmissionDenied) as exc:
        svc.aggregate("a", "count", filters={"industry": "tech"})
    assert exc.value.rule == "D3"
    assert svc.describe_dataset("a")["budget"]["remaining"] == 0
    assert svc.describe_dataset("b")["budget"]["remaining"] == 2
    svc.aggregate("b", "count", filters={"industry": "tech"})


def test_tainted_context_admits_count_only(svc):
    with pytest.raises(AdmissionDenied) as exc:
        svc.aggregate("a", "sum", "revenue_2025", {"industry": "tech"}, taint=1)
    assert exc.value.rule == "D4-surface"
    assert svc.aggregate("a", "count", filters={"industry": "tech"}, taint=1)["value"] == 3


def test_decryption_out_of_range_is_a_traced_denial():
    settings = replace(DEMO_SETTINGS, disclosure=FAST,
                       decryption=DecryptionSettings(max_value=1000, table_size=None))
    svc = demo_service(settings)
    with pytest.raises(AdmissionDenied) as exc:
        svc.aggregate("a", "sum", "revenue_2025", {"industry": "tech"})
    assert exc.value.rule == "decryption-range"
    assert list(svc.trace)[-1].audit.detail == "decryption-range"


def test_argument_errors_are_specific_and_data_independent(svc):
    with pytest.raises(ArgumentError, match="sealed column"):
        svc.aggregate("a", "sum", "industry")
    with pytest.raises(ArgumentError, match="cannot filter on"):
        svc.aggregate("a", "count", filters={"revenue_2025": "1"})
    with pytest.raises(ArgumentError, match="var is not enabled"):
        svc.aggregate("a", "var", "revenue_2025", {"industry": "tech"})
    with pytest.raises(ArgumentError, match="unknown tool"):
        svc.invoke("drop_table", "a")
    with pytest.raises(ArgumentError, match="invalid arguments"):
        svc.invoke("aggregate", "a", {"function": "sum", "sql": "1=1"})


# -- ingest and schema ----------------------------------------------------------------


def _schema(**extra):
    return Schema(columns=(
        ColumnSpec("amount", "sealed", scale=2, **extra),
        ColumnSpec("team", "open"),
    ))


def _settings(k=2):
    return GatewaySettings(admission=AdmissionSettings(min_query_set_size=k, window="total"),
                           decryption=SMALL, disclosure=FAST)


def test_decimal_values_are_exact_and_band_mode_hides_them():
    svc = TokenisGatewayService(_schema(), KEY, _settings())
    for i, (amount, team) in enumerate([("10.005", "x"), (2.5, "x"), (1, "y"), ("-0.10", "y")]):
        svc.ingest(str(i), {"amount": amount, "team": team})
    assert svc.aggregate("a", "sum", "amount", {"team": "x"})["value"] == pytest.approx(12.51)
    banded = TokenisGatewayService(_schema(result_mode="band"), KEY, _settings())
    for i, amount in enumerate([1500, 1600, 10, 20]):
        banded.ingest(str(i), {"amount": amount, "team": "x" if i < 2 else "y"})
    assert banded.aggregate("a", "sum", "amount", {"team": "x"})["value"] == "[2,000, 5,000)"


def test_variance(svc):
    service = TokenisGatewayService(_schema(allow_variance=True), KEY, _settings())
    for i, (amount, team) in enumerate([(1, "x"), (3, "x"), (5, "y"), (5, "y")]):
        service.ingest(str(i), {"amount": amount, "team": team})
    assert service.aggregate("a", "var", "amount", {"team": "x"})["value"] == pytest.approx(1.0)


def test_ingest_validation_and_sealing():
    svc = TokenisGatewayService(_schema(), KEY, _settings())
    with pytest.raises(ValueError, match="missing value"):
        svc.ingest("1", {"amount": 1})
    with pytest.raises(ValueError, match="expected a number"):
        svc.ingest("1", {"amount": "12abc", "team": "x"})
    with pytest.raises(ValueError, match="finite"):
        svc.ingest("1", {"amount": "Infinity", "team": "x"})
    svc.ingest("1", {"amount": 1, "team": "x"})
    with pytest.raises(ValueError, match="duplicate"):
        svc.ingest("1", {"amount": 1, "team": "x"})
    with pytest.raises(RuntimeError, match="at least"):
        svc.seal()  # 1 record < 2k
    for i in range(2, 5):
        svc.ingest(str(i), {"amount": i, "team": "x" if i % 2 else "y"})
    svc.aggregate("a", "count", filters={"team": "x"})
    with pytest.raises(RuntimeError, match="sealed"):
        svc.ingest("9", {"amount": 1, "team": "x"})


def test_schema_validation():
    with pytest.raises(ValueError):
        ColumnSpec("Bad Name", "open")
    with pytest.raises(ValueError):
        ColumnSpec("x", "secret")
    with pytest.raises(ValueError):
        ColumnSpec("x", "open", scale=2)
    with pytest.raises(ValueError):
        Schema(columns=(ColumnSpec("x", "open"),))  # no sealed column
    with pytest.raises(ValueError):
        Schema(columns=(ColumnSpec("x", "sealed"),), embedding_column="emb")  # needs an entity


def test_band():
    assert band(0) == "0"
    assert band(1) == "[1, 2)"
    assert band(4_250_000) == "[2,000,000, 5,000,000)"
    assert band(-7) == "(-10, -5]"
    assert band(0.03) == "[0.02, 0.05)"


# -- concurrency (audit finding: concurrent calls bypassed D2) ----------------------


def _race_ledger(seal: bool) -> TokenisGatewayService:
    schema = Schema(columns=(ColumnSpec("revenue", "sealed"), ColumnSpec("industry", "open"),
                             ColumnSpec("region", "open")))
    svc = TokenisGatewayService(schema, KEY, _settings(k=3))
    rows = [("tech", "gangnam", 100), ("tech", "gangnam", 200), ("tech", "gangnam", 300),
            ("tech", "jongno", 4242)] + [("finance", "busan", 10 * i) for i in range(6)]
    for i, (industry, region, revenue) in enumerate(rows):
        svc.ingest(str(i), {"industry": industry, "region": region, "revenue": revenue})
    if seal:
        svc.seal()
    return svc


@pytest.mark.parametrize("presealed", [False, True])
def test_concurrent_differencing_pair_is_never_both_admitted(presealed):
    """sum(tech) - sum(tech, gangnam) = the one tech/jongno record. Each
    query alone is admissible; together they must never both be."""
    for _ in range(40):
        svc = _race_ledger(presealed)
        barrier = threading.Barrier(2)
        admitted = []

        def call(filters, svc=svc, barrier=barrier, admitted=admitted):
            barrier.wait()
            try:
                svc.invoke("aggregate", "mallory",
                           {"function": "sum", "column": "revenue", "filters": filters})
                admitted.append(filters)
            except AdmissionDenied:
                pass

        threads = [threading.Thread(target=call, args=(f,)) for f in
                   ({"industry": "tech"}, {"industry": "tech", "region": "gangnam"})]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(admitted) == 1, admitted


def test_concurrent_calls_respect_the_budget_exactly_and_keep_the_trace_intact():
    settings = replace(DEMO_SETTINGS, disclosure=FAST,
                       admission=replace(DEMO_SETTINGS.admission, budget=25))
    svc = demo_service(settings)
    svc.seal()
    admitted = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        for _ in range(5):
            try:
                svc.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "tech"}})
                admitted.append(1)
            except AdmissionDenied:
                pass

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(admitted) == 25
    entries = list(svc.trace)
    assert len(entries) == 80
    assert [e.index for e in entries] == list(range(80))
    assert svc.trace.verify_chain()


def test_admission_decisions_never_overlap(monkeypatch):
    """Deterministic form of the race above: with a sleep inside every
    decision, any two unserialised calls would overlap. The service lock
    must keep the peak at one."""
    active = peak = 0
    guard = threading.Lock()
    original = AdmissionPolicy.decide

    def slow_decide(self, query, context):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.003)
        try:
            return original(self, query, context)
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(AdmissionPolicy, "decide", slow_decide)
    svc = demo_service(latency_granularity_ms=1.0)
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        for _ in range(3):
            try:
                svc.invoke("aggregate", "a", {"function": "sum", "column": "revenue_2025",
                                              "filters": {"industry": "tech"}})
            except AdmissionDenied:
                pass

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1


def test_trace_appends_are_atomic_on_their_own():
    trace = DisclosureTrace()
    barrier = threading.Barrier(16)
    record = AuditRecord(principal="p", obj_ref="o", purpose="x", policy_version="v",
                         decision="permit")

    def worker():
        barrier.wait()
        for _ in range(50):
            trace.record_aggregate_result(record, 1)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [e.index for e in trace] == list(range(800))
    assert trace.verify_chain()
