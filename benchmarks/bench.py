#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tokenis performance benchmarks. Writes ``benchmarks/results.json`` and
prints a Markdown report (the source of ``BENCHMARKS.md``).

    python benchmarks/bench.py                 # 10k and 100k records + HTTP load test
    python benchmarks/bench.py --sizes 10000 100000 1000000

What is measured, and how:

- **crypto**: the Rust core through the Python bindings -- single and batch
  encryption, masked homomorphic sums, and decryption for the table/range
  combinations the gateway actually builds.
- **gateway**: one fresh process per dataset size (so peak memory is that
  size's alone). A synthetic ledger with two sealed columns, three open
  columns and a unique token column is loaded with the batched loader, then
  a fixed, seeded mix of tool calls runs through ``invoke`` -- the gateway's
  own service time, *without* the W6 latency padding a client sees.
- **http**: ``tokenis-mcp serve`` in a subprocess over a 100k-record CSV,
  API-key authentication on, driven by concurrent MCP clients over
  Streamable HTTP. This is the end-to-end latency a client sees (padding
  included, plus transport overhead), authentication, and that state
  survives a restart.
- **w6**: the latency quantum where it is defined -- around each tool call
  at the server -- under the same concurrency, asserted to hold.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import platform
import random
import resource
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List

HERE = Path(__file__).resolve().parent


def pct(samples: List[float], q: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def summarize(samples_s: List[float]) -> Dict[str, float]:
    ms = [x * 1000 for x in samples_s]
    return {"p50_ms": round(pct(ms, 0.5), 3), "p99_ms": round(pct(ms, 0.99), 3),
            "max_ms": round(max(ms), 3), "n": len(ms)}


def timed(fn: Callable[[], Any], reps: int) -> Dict[str, float]:
    samples = []
    for _ in range(reps):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return summarize(samples)


# -- crypto primitives ------------------------------------------------------------


def bench_crypto() -> Dict[str, Any]:
    from tokenis._core import CiphertextVector, Decryptor, PrivateKey, encrypt

    sk = PrivateKey.generate()
    pk = sk.public_key()
    out: Dict[str, Any] = {"encrypt_single": timed(lambda: encrypt(pk, 123_456), 2000)}
    values = list(range(100_000))
    vec = CiphertextVector(pk)
    start = time.perf_counter()
    vec.extend_encrypt(values)
    elapsed = time.perf_counter() - start
    out["encrypt_batch_100k"] = {"seconds": round(elapsed, 3), "per_second": round(len(values) / elapsed)}
    half = bytes(i % 2 for i in range(len(values)))
    out["sum_where_100k_half"] = timed(lambda: vec.sum_where(half), 20)
    total = vec.sum_where(half)
    expected = sum(v for v in values if v % 2)
    for label, max_value, table in (
        ("decrypt_range_2^32_table_2^20", 1 << 32, 1 << 20),
        ("decrypt_range_2^36_table_2^22", 1 << 36, 1 << 22),
        ("decrypt_range_2^40_table_2^24", 1 << 40, 1 << 24),
    ):
        start = time.perf_counter()
        dec = Decryptor(sk, max_value, table_size=table)
        build = time.perf_counter() - start
        assert dec.decrypt(total) == expected
        out[label] = {"build_s": round(build, 3), **timed(lambda d=dec: d.decrypt(total), 10)}
    return out


# -- gateway (one size per process) --------------------------------------------------


def synthetic_rows(n: int, seed: int = 20260923) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        industry = f"industry-{rng.randrange(20):02d}"
        base = 400 + 100 * (int(industry[-2:]) % 7)
        r24 = round(base * rng.lognormvariate(0, 0.8), 1)
        rows.append({
            "id": f"C{i:07d}", "customer": f"customer-{i}", "industry": industry,
            "region": f"region-{rng.randrange(50):02d}", "size_band": rng.choice(["S", "M", "L"]),
            "revenue_2024": r24, "revenue_2025": round(r24 * rng.uniform(0.8, 1.4), 1),
        })
    return rows


def schema_and_settings(budget: int = 10**6):
    from tokenis.gateway.schema import (
        AdmissionSettings,
        ColumnSpec,
        GatewaySettings,
        RevealPurpose,
        Schema,
    )

    schema = Schema(
        columns=(
            ColumnSpec("customer", "token", entity=True),
            ColumnSpec("industry", "open"), ColumnSpec("region", "open"),
            ColumnSpec("size_band", "open"),
            ColumnSpec("revenue_2024", "sealed", unit="KRW million", scale=1),
            ColumnSpec("revenue_2025", "sealed", unit="KRW million", scale=1),
        ),
        id_column="id",
    )
    settings = GatewaySettings(
        admission=AdmissionSettings(min_query_set_size=10, budget=budget, window="total"),
        purposes=(RevealPurpose("benchmark", "Benchmark disclosure"),),
    )
    return schema, settings


def bench_gateway_size(n: int) -> Dict[str, Any]:
    from tokenis.gateway.service import AdmissionDenied, TokenisGatewayService

    schema, settings = schema_and_settings()
    rows = synthetic_rows(n)
    svc = TokenisGatewayService(schema, b"b" * 32, settings)
    start = time.perf_counter()
    for i in range(0, n, 4096):
        svc.ingest_many((r["id"], r, None) for r in rows[i:i + 4096])
    ingest = time.perf_counter() - start
    del rows
    start = time.perf_counter()
    svc.seal()
    seal = time.perf_counter() - start

    rng = random.Random(7)

    def filters() -> Dict[str, str]:
        f = {"industry": f"industry-{rng.randrange(20):02d}"}
        if rng.random() < 0.6:
            f["region"] = f"region-{rng.randrange(50):02d}"
        if rng.random() < 0.4:
            f["size_band"] = rng.choice(["S", "M", "L"])
        return f

    mix = {
        "aggregate_sum": lambda: ("aggregate", {"function": "sum", "column": "revenue_2025",
                                                "filters": filters()}),
        "aggregate_avg": lambda: ("aggregate", {"function": "avg", "column": "revenue_2024",
                                                "filters": filters()}),
        "aggregate_count": lambda: ("aggregate", {"function": "count", "filters": filters()}),
        "group_by_industry": lambda: ("group_by", {"key": "industry", "column": "revenue_2025"}),
        "compare_periods": lambda: ("compare_periods", {"column_a": "revenue_2024",
                                                        "column_b": "revenue_2025",
                                                        "filters": filters()}),
        "exists": lambda: ("exists", {"filters": filters()}),
        "disclose_ratio": lambda: ("disclose_ratio", {"column": "revenue_2025",
                                                      "numerator_filters": filters(),
                                                      "denominator_filters": filters(),
                                                      "purpose": "benchmark"}),
        "describe_dataset": lambda: ("describe_dataset", {}),
    }
    reps = {"group_by_industry": 10}
    tools: Dict[str, Any] = {}
    for name, make in mix.items():
        samples, denied = [], 0
        for _ in range(reps.get(name, 150)):
            tool, args = make()
            start = time.perf_counter()
            try:
                svc.invoke(tool, "bench", args)
            except AdmissionDenied:
                denied += 1
            samples.append(time.perf_counter() - start)
        tools[name] = {**summarize(samples), "denied": denied}
    return {
        "records": n,
        "ingest_s": round(ingest, 2),
        "ingest_rows_per_s": round(n / ingest),
        "seal_s": round(seal, 2),
        "admission_cells": int(svc._admission.n) if svc._admission else None,
        "tools": tools,
        "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                             / (1e6 if sys.platform == "darwin" else 1e3)),
    }


def run_size_in_subprocess(n: int) -> Dict[str, Any]:
    proc = subprocess.run([sys.executable, __file__, "--one-size", str(n)],
                          capture_output=True, text=True, check=True)
    return dict(json.loads(proc.stdout.strip().splitlines()[-1]))


# -- end-to-end HTTP ------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


CONFIG = """
[tenant]
name = "bench"
[data]
path = "rows.csv"
id_column = "id"
[[columns]]
name = "customer"
protection = "token"
entity = true
[[columns]]
name = "industry"
protection = "open"
[[columns]]
name = "region"
protection = "open"
[[columns]]
name = "size_band"
protection = "open"
[[columns]]
name = "revenue_2024"
protection = "sealed"
scale = 1
[[columns]]
name = "revenue_2025"
protection = "sealed"
scale = 1
[admission]
min_query_set_size = 10
budget = 100000
window = "total"
[disclosure]
latency_granularity_ms = {granularity}
[state]
dir = "state"
audit_key_env = "TOKENIS_AUDIT_KEY"
[server]
transport = "http"
port = {port}
max_concurrency = 16
[auth]
mode = "api_keys"
api_keys_file = "state/keys.json"
"""


def bench_http(records: int, clients: int, calls: int, granularity: float) -> Dict[str, Any]:
    import httpx2
    from mcp.client.client import Client
    from mcp.client.streamable_http import streamable_http_client

    work = Path(tempfile.mkdtemp(prefix="tokenis-bench-"))
    rows = synthetic_rows(records)
    with (work / "rows.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    port = _free_port()
    (work / "tokenis.toml").write_text(CONFIG.format(port=port, granularity=granularity))
    env = {**os.environ, "TOKENIS_TOKENIZER_KEY": "ab" * 32, "TOKENIS_AUDIT_KEY": "cd" * 32}
    cli = [sys.executable, "-m", "tokenis.cli", "--log-level", "WARNING"]
    key = subprocess.run([*cli, "keys", "create", "bench@example.com", "--config",
                          str(work / "tokenis.toml")], env=env, capture_output=True, text=True,
                         check=True).stdout.strip()

    def start_server() -> "tuple[subprocess.Popen[bytes], float]":
        started = time.perf_counter()
        proc = subprocess.Popen([*cli, "serve", "--config", str(work / "tokenis.toml")], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return proc, time.perf_counter() - started
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError(proc.stderr.read().decode() if proc.stderr else "server died")
                time.sleep(0.1)

    url = f"http://127.0.0.1:{port}/mcp"
    rng = random.Random(3)

    def call_args() -> "tuple[str, Dict[str, Any]]":
        f = {"industry": f"industry-{rng.randrange(20):02d}", "region": f"region-{rng.randrange(50):02d}"}
        return rng.choice([
            ("aggregate", {"function": "sum", "column": "revenue_2025", "filters": f}),
            ("aggregate", {"function": "count", "filters": {"industry": f["industry"]}}),
            ("exists", {"filters": f}),
            ("compare_periods", {"column_a": "revenue_2024", "column_b": "revenue_2025",
                                 "filters": {"industry": f["industry"]}}),
        ])

    async def client_session(latencies: List[float], outcomes: Dict[str, int]) -> None:
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"},
                                  timeout=httpx2.Timeout(60.0))
        async with http, Client(streamable_http_client(url, http_client=http)) as client:
            for _ in range(calls):
                tool, args = call_args()
                start = time.perf_counter()
                result = await client.call_tool(tool, args)
                latencies.append(time.perf_counter() - start)
                outcomes["denied" if result.is_error else "ok"] += 1

    async def load() -> "tuple[List[float], Dict[str, int], float]":
        latencies: List[float] = []
        outcomes = {"ok": 0, "denied": 0}
        start = time.perf_counter()
        await asyncio.gather(*(client_session(latencies, outcomes) for _ in range(clients)))
        return latencies, outcomes, time.perf_counter() - start

    async def remaining() -> int:
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"})
        async with http, Client(streamable_http_client(url, http_client=http)) as client:
            result = await client.call_tool("describe_dataset", {})
            return int(json.loads(result.content[0].text)["budget"]["remaining"])

    proc, startup = start_server()
    try:
        unauthorized = httpx2.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                              "params": {}},
                                   headers={"Accept": "application/json, text/event-stream"}).status_code
        latencies, outcomes, wall = asyncio.run(load())
        before_restart = asyncio.run(remaining())
    finally:
        proc.terminate()
        proc.wait(timeout=30)
    proc, restart = start_server()
    try:
        after_restart = asyncio.run(remaining())
        audit = subprocess.run([*cli, "audit", "verify", "--config", str(work / "tokenis.toml")],
                               env=env, capture_output=True, text=True, check=True)
    finally:
        proc.terminate()
        proc.wait(timeout=30)

    excess = [x * 1000 - (x * 1000 // granularity) * granularity for x in latencies]
    return {
        "records": records,
        "clients": clients,
        "calls": len(latencies),
        "outcomes": outcomes,
        "throughput_calls_per_s": round(len(latencies) / wall, 1),
        "latency": summarize(latencies),
        "granularity_ms": granularity,
        "transport_excess_over_quantum": summarize([e / 1000 for e in excess]),
        "startup_s_incl_load": round(startup, 2),
        "restart_s_incl_replay": round(restart, 2),
        "unauthenticated_status": unauthorized,
        "budget_persisted_across_restart": before_restart == after_restart,
        "audit_verify": json.loads(audit.stdout),
    }


def bench_w6_server_side(records: int, clients: int, calls: int, granularity: float) -> Dict[str, Any]:
    """W6 where it is defined: at the server, around each tool call, under
    the same concurrency as the HTTP test but without a network in between."""
    from tokenis.gateway.service import TokenisGatewayService
    from tokenis.mcp_server.server import create_server, fixed_principal

    schema, settings = schema_and_settings()
    from dataclasses import replace

    settings = replace(settings, disclosure=replace(settings.disclosure,
                                                    latency_granularity_ms=granularity))
    svc = TokenisGatewayService(schema, b"b" * 32, settings)
    rows = synthetic_rows(records)
    for i in range(0, records, 4096):
        svc.ingest_many((r["id"], r, None) for r in rows[i:i + 4096])
    server = create_server(svc, principal_resolver=fixed_principal("bench"))
    rng = random.Random(5)

    async def client(samples: List[float]) -> None:
        for _ in range(calls):
            f = {"industry": f"industry-{rng.randrange(20):02d}"}
            if rng.random() < 0.5:
                f["region"] = f"region-{rng.randrange(50):02d}"
            if rng.random() < 0.2:
                # A well-formed token that matches no record: a fast D1
                # denial (schema-invalid values are rejected by the SDK
                # before any gateway code, independent of the data).
                f = {"customer": "0" * 32}
            start = time.perf_counter()
            try:
                await server.call_tool("aggregate", {"function": "sum", "column": "revenue_2025",
                                                     "filters": f})
            except Exception:  # noqa: BLE001 -- denials are part of the mix
                pass
            samples.append(time.perf_counter() - start)

    async def run() -> List[float]:
        samples: List[float] = []
        await asyncio.gather(*(client(samples) for _ in range(clients)))
        return samples

    samples = asyncio.run(run())
    excess = [x * 1000 - (x * 1000 // granularity) * granularity for x in samples]
    buckets = sorted({int(x * 1000 // granularity) for x in samples})
    return {"calls": len(samples), "clients": clients, "buckets_used": buckets,
            "excess_over_quantum": summarize([e / 1000 for e in excess])}


# -- report ---------------------------------------------------------------------------


def markdown(results: Dict[str, Any]) -> str:
    env = results["environment"]
    lines = [
        f"Measured {results['date']} on {env['machine']} ({env['cpus']} cores, "
        f"{env['memory_gb']} GB), {env['os']}, Python {env['python']}; 1/5/15-minute load "
        f"average at start {env['load_average_at_start']}.",
        "",
        "### Cryptographic primitives (Rust core via Python)",
        "",
        "| Operation | Result |",
        "|---|---|",
    ]
    c = results["crypto"]
    lines.append(f"| Encrypt one value | p50 {c['encrypt_single']['p50_ms']} ms |")
    lines.append(f"| Encrypt 100,000 values (batch, all cores) | {c['encrypt_batch_100k']['seconds']} s "
                 f"({c['encrypt_batch_100k']['per_second']:,}/s) |")
    lines.append(f"| Homomorphic sum of 50,000 of 100,000 ciphertexts | p50 "
                 f"{c['sum_where_100k_half']['p50_ms']} ms |")
    for key, label in (("decrypt_range_2^32_table_2^20", "range 2^32, table 2^20 (8 MiB)"),
                       ("decrypt_range_2^36_table_2^22", "range 2^36, table 2^22 (32 MiB)"),
                       ("decrypt_range_2^40_table_2^24", "range 2^40, table 2^24 (128 MiB)")):
        d = c[key]
        lines.append(f"| Decrypt, {label} | build {d['build_s']} s, decrypt p50 {d['p50_ms']} ms |")
    lines += ["", "### Gateway service time (no latency padding)", "",
              "| Records | Load | Seal | Cells | Peak RSS | sum p50/p99 | avg p50 | count p50 "
              "| group_by (20 groups) p50 | compare p50 | ratio p50 |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for g in results["gateway"]:
        t = g["tools"]
        lines.append(
            f"| {g['records']:,} | {g['ingest_s']} s ({g['ingest_rows_per_s']:,}/s) | {g['seal_s']} s "
            f"| {g['admission_cells']:,} | {g['peak_rss_mb']:,} MB "
            f"| {t['aggregate_sum']['p50_ms']} / {t['aggregate_sum']['p99_ms']} ms "
            f"| {t['aggregate_avg']['p50_ms']} ms | {t['aggregate_count']['p50_ms']} ms "
            f"| {t['group_by_industry']['p50_ms']} ms | {t['compare_periods']['p50_ms']} ms "
            f"| {t['disclose_ratio']['p50_ms']} ms |")
    w = results.get("w6")
    if w:
        lines += ["", "### Uniform latency (W6), server side", "",
                  f"{w['calls']} `aggregate` calls from {w['clients']} concurrent clients, admitted and "
                  f"denied mixed: every call landed in latency bucket(s) {w['buckets_used']} of "
                  f"{results['granularity_ms']} ms, at most {w['excess_over_quantum']['max_ms']} ms "
                  f"past the boundary (p99 {w['excess_over_quantum']['p99_ms']} ms)."]
    h = results.get("http")
    if h:
        lines += ["", "### End to end over Streamable HTTP (authenticated, padding included)", "",
                  f"`tokenis-mcp serve` over {h['records']:,} records, {h['clients']} concurrent "
                  f"MCP clients, {h['calls']} calls ({h['outcomes']['ok']} answered, "
                  f"{h['outcomes']['denied']} denied by policy):", "",
                  f"- Throughput: {h['throughput_calls_per_s']} calls/s",
                  f"- Latency seen by clients: p50 {h['latency']['p50_ms']} ms, p99 "
                  f"{h['latency']['p99_ms']} ms (quantum {h['granularity_ms']} ms). HTTP, JSON "
                  f"and queueing add p50 {h['transport_excess_over_quantum']['p50_ms']} ms / p99 "
                  f"{h['transport_excess_over_quantum']['p99_ms']} ms on top of the padded "
                  f"server time; that overhead depends on load, not on the data.",
                  f"- Start-up including load and encryption: {h['startup_s_incl_load']} s; "
                  f"restart including admission-history replay: {h['restart_s_incl_replay']} s",
                  f"- Unauthenticated request: HTTP {h['unauthenticated_status']}; budget "
                  f"persisted across restart: {h['budget_persisted_across_restart']}; audit trail "
                  f"{h['audit_verify']['entries']} entries, signed: {h['audit_verify']['signed']}"]
    return "\n".join(lines) + "\n"


REPORT_HEADER = """# Benchmarks

Numbers below are generated by `benchmarks/bench.py` from `benchmarks/results.json`;
rerun it on your own hardware with:

```bash
python benchmarks/bench.py --sizes 10000 100000 1000000
python benchmarks/bench.py --report          # rewrite this file from results.json
```

How to read them:

- **Gateway service time** is the gateway's own work for one tool call
  (admission control, homomorphic summation, decryption, audit), measured
  without the uniform-latency padding. What a client sees is this rounded
  *up* to the latency quantum (250 ms by default; configurable), which is
  what the W6 and HTTP sections measure.
- Each sealed column's decryptor is sized to that column's own bound, so
  decryption cost depends on the data's magnitude, not on a worst case.
- The admission-control audit runs over *cells* -- groups of records no
  admissible query can tell apart -- so its cost does not grow with the
  record count (3,000 cells here for 10k to 1M records).
- Laptop measurements are sensitive to background load; the environment
  line records the load average when the run started.

"""


def write_report() -> None:
    results = json.loads((HERE / "results.json").read_text())
    (HERE.parent / "BENCHMARKS.md").write_text(REPORT_HEADER + markdown(results))
    print("wrote BENCHMARKS.md")


def environment() -> Dict[str, Any]:
    machine = platform.machine()
    if sys.platform == "darwin":
        machine = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True).stdout.strip() or machine
    mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30
    return {"machine": machine, "cpus": os.cpu_count(), "memory_gb": round(mem),
            "load_average_at_start": [round(x, 1) for x in os.getloadavg()],
            "os": f"{platform.system()} {platform.release()}", "python": platform.python_version()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", type=int, nargs="+", default=[10_000, 100_000])
    parser.add_argument("--http-records", type=int, default=100_000)
    parser.add_argument("--http-clients", type=int, default=32)
    parser.add_argument("--http-calls", type=int, default=25)
    parser.add_argument("--granularity-ms", type=float, default=250.0)
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument("--one-size", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--report", action="store_true",
                        help="only rewrite BENCHMARKS.md from benchmarks/results.json")
    args = parser.parse_args()
    if args.report:
        write_report()
        return
    if args.one_size:
        print(json.dumps(bench_gateway_size(args.one_size)))
        return
    results: Dict[str, Any] = {"date": time.strftime("%Y-%m-%d"), "environment": environment()}
    results["crypto"] = bench_crypto()
    results["gateway"] = [run_size_in_subprocess(n) for n in args.sizes]
    results["granularity_ms"] = args.granularity_ms
    results["w6"] = bench_w6_server_side(args.http_records, args.http_clients, args.http_calls,
                                         args.granularity_ms)
    if not args.skip_http:
        results["http"] = bench_http(args.http_records, args.http_clients, args.http_calls,
                                     args.granularity_ms)
    (HERE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(markdown(results))
    w = results["w6"]
    assert len(w["buckets_used"]) == 1 and w["excess_over_quantum"]["max_ms"] < 0.2 * args.granularity_ms, \
        "server-side latency padding did not hold"
    if not args.skip_http:
        h = results["http"]
        assert h["unauthenticated_status"] == 401
        assert h["budget_persisted_across_restart"]


if __name__ == "__main__":
    main()
