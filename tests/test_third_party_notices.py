# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The third-party notices generator must read `cargo tree` output the same
way whatever the cargo version (CI once saw "(*)" leak into licenses)."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "third_party_notices.py"
spec = importlib.util.spec_from_file_location("third_party_notices", SCRIPT)
tpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpn)


@pytest.mark.parametrize("line", [
    "ff v0.13.1 | MIT/Apache-2.0",
    "ff v0.13.1 | MIT/Apache-2.0 (*)",
    "ff v0.13.1 | MIT/Apache-2.0  (*)",
    "ff v0.13.1 | MIT/Apache-2.0(*)",
    "ff v0.13.1 | MIT/Apache-2.0 (*)",
    "ff v0.13.1 | MIT/Apache-2.0\t(*)",
])
def test_the_dedupe_marker_never_reaches_the_license(line):
    assert tpn.parse_line(line) == ("ff", "0.13.1", "MIT/Apache-2.0")


def test_our_own_crates_and_proc_macros_are_skipped():
    assert tpn.parse_line("tokenis-core v0.1.0 (/x/crates/tokenis-core) | Apache-2.0") is None
    assert tpn.parse_line("serde_derive v1.0.0 (proc-macro) | MIT OR Apache-2.0") is None
    assert tpn.parse_line("pyo3 v0.29.2 | MIT OR Apache-2.0") == ("pyo3", "0.29.2", "MIT OR Apache-2.0")
