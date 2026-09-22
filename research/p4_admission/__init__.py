# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""research.p4_admission — reproduction package for P4 (Admission Control for Probabilistic Callers).

Paper: "Admission Control for Probabilistic Callers: Bounding Disclosure When the
Query Planner Is a Language Model" (Lee, Shim, Lee; J1729Labs, 2026).
See ``research/p4_admission/README.md`` for the honesty disclaimer, the paper-section
to file mapping, and instructions for running ``verify_claims.py``.

``admission.py``'s public API (``AdmissionPolicy``, ``QueryContext``, ``Query``,
``Decision``, the ``Predicate`` algebra, ``SubjectScopedBudget`` /
``CredentialScopedBudget``, ``RREFBasis``) is intended to be imported, unchanged, as
``tokenis/gateway/admission.py`` in a later milestone. Import it with plain absolute
imports, e.g.::

    from research.p4_admission.admission import AdmissionPolicy, QueryContext, Query

so that the module keeps working whether it is exercised from inside this package's
own tests or from a future ``tokenis/gateway/`` that imports it directly.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
