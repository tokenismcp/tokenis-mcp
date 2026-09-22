# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The semantic module (P2 §3.4, ``G_sem``): tokenization of
:class:`~tokenis.semantic.tokenizer.ProtectionClass.TOKEN` attributes on
egress/ingress, and the generalization hierarchy used by the ``group_by``
and ``aggregate`` tools' quasi-identifier handling.
"""

from tokenis.semantic.tokenizer import (
    GeneralizationHierarchy,
    ProtectionClass,
    ScopedTokenizer,
)

__all__ = ["GeneralizationHierarchy", "ProtectionClass", "ScopedTokenizer"]
