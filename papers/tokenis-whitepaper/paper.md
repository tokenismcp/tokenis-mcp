# Tokenis: Cryptographic Pseudonymization and Idea Protection Using EC-ElGamal for Privacy-Preserving AI Systems

**4Chains Inc. — February 4, 2026** · [paper.pdf](./paper.pdf) · License: [CC BY 4.0](../LICENSE-CC-BY-4.0)

> The full whitepaper, with the formal security model, the three security
> properties and their proofs, and the integration with TorusDB, is in
> [`paper.pdf`](./paper.pdf). This page is a navigation aid, not a substitute for it.

## Abstract

As AI systems increasingly rely on private and proprietary data, conventional data
anonymization and tokenization techniques have proven insufficient to prevent information
leakage during retrieval-augmented generation (RAG) and autonomous AI agent execution.
Surface-level identifier masking leaves the deeper semantic structure of domain knowledge
(decision rules, scoring formulas, and operational procedures) fully exposed to
reconstruction through iterative querying.

The paper presents Tokenis, a cryptographic pseudonymization framework that combines
Named Entity Recognition (NER)-based data selection with elliptic-curve ElGamal
(EC-ElGamal) encryption to protect both personal data and high-value domain ideas. Unlike
approaches that focus solely on personally identifiable information (PII), Tokenis
introduces an *idea protection protocol* that prevents the reconstruction and replication
of proprietary rules, strategies and algorithms while still enabling AI-driven reasoning
over the protected knowledge.

The paper gives a formal security model grounded in the Decisional Diffie-Hellman (DDH)
assumption, proves three core security properties (PII confidentiality, idea
reconstruction resistance and adaptive query safety), and demonstrates end-to-end
integration with the TorusDB RAG platform.

## Relation to this repository

This whitepaper describes the construction that the `tokenis/` gateway puts into
practice. The admission-control and disclosure-boundary arguments are in the J1729Labs
series: [P2](../p2-disclosure-boundaries/paper.md), [P3](../p3-leakage-quantification/paper.md)
and [P4](../p4-admission-control/paper.md).
