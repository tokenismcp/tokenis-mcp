# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The gateway: compute (``G_com``), admission (``G_adm``) and reveal.

See P2 §3.4 for the three-module split this package mirrors:
:mod:`tokenis.gateway.compute` (aggregate evaluation over ciphertext, P2's
``G_com``), :mod:`tokenis.gateway.admission` (the P4 admission-control
engine, P2's ``G_adm``), and :mod:`tokenis.gateway.reveal` (the gated,
audited Reveal operation, P2 Definition 15).
"""
