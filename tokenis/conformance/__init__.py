# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for the well-formedness conditions W1-W6
(``tokenis/spec/well-formedness.md``, P2 Definition 17).

These tests run against this repository's own reference implementation via
:class:`~tokenis.conformance.reference_gateway.ReferenceGateway`. A third
party implementing the Tokenis spec independently can reuse these tests by
providing an equivalent harness exposing the same small surface (see that
module's docstring).
"""
