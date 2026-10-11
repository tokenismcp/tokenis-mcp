# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Comparing untrusted values: any text gives a plain yes or no, never a crash
(found by nightly fuzzing: hmac.compare_digest raises on non-ASCII str)."""
import json

import pytest

from tokenis.audit.trace import AuditRecord, DisclosureTrace, TraceIntegrityError
from tokenis.console_auth import SessionSigner
from tokenis.safe import equal


def test_equal_handles_any_text():
    assert equal("abc", "abc") and not equal("abc", "abd")
    assert equal("é한", "é한") and not equal("é한", "e한")
    assert equal(b"abc", "abc") and not equal("abc", "ab")
    assert not equal("\ud800", "x") and equal("\ud800", "\ud800")  # lone surrogates, as JSON can carry
    assert not equal("", "a") and equal("", "")


@pytest.mark.parametrize("mac", ["\x80" + "0" * 63, "é" * 64, "한" * 8, "\ud800"])
def test_a_trail_with_a_non_ascii_mac_is_reported_as_tampered(tmp_path, mac):
    key = b"a" * 32
    path = tmp_path / "trace.jsonl"
    trace = DisclosureTrace(path=path, hmac_key=key)
    for i in range(3):
        trace.record_denial(AuditRecord(principal="p", obj_ref=f"aggregate:sum(x)|k={i}", purpose="aggregate",
                                        policy_version="v", decision="deny", timestamp=1e9 + i))
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["mac"] = mac
    lines[0] = json.dumps(entry, sort_keys=True)  # ensure_ascii escapes the surrogate, as a real file would
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(TraceIntegrityError):
        list(DisclosureTrace(path=path, hmac_key=key))


@pytest.mark.parametrize("cookie", ["abc.é", "é.é", "a.\x80", "한.한", "x." + "é" * 40])
def test_a_forged_session_cookie_with_non_ascii_is_refused(cookie):
    signer = SessionSigner(b"k" * 32, "session")
    assert signer.verify(cookie) is None
