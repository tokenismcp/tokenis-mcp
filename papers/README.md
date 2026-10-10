# Papers

The Tokenis deliverable programme publishes cryptographic constructions and formal
security arguments through **J1729Labs** (the P-series), product whitepapers and
benchmarks through **4Chains Inc.** (see [`reports/SUMMARY.md`](../reports/SUMMARY.md)).
This directory holds the J1729Labs paper series and the Tokenis whitepaper; the code each paper commits to releasing lives under
[`research/`](../research/).

| ID | Title | Status |
|----|-------|--------|
| P1 | EC-based homomorphic encryption with multiplication | Referenced by P2–P4 as the underlying cryptographic construction. Not yet included in this repository — the `tokenis/crypto` module is an independent reference implementation of the same *properties* (Definition 3 of P2: IND-CPA, additively homomorphic), not a reproduction of P1 itself. |
| [Tokenis whitepaper](./tokenis-whitepaper/paper.md) | Tokenis: cryptographic pseudonymization and idea protection with EC-ElGamal (4Chains Inc., February 2026) | Complete. [paper.pdf](./tokenis-whitepaper/paper.pdf) |
| [P2](./p2-disclosure-boundaries/paper.md) | Disclosure Boundaries — threat model and leakage formalisation | Complete. [paper.pdf](./p2-disclosure-boundaries/paper.pdf) |
| [P3](./p3-leakage-quantification/paper.md) | What a Token Does Not Hide — leakage quantification and disclosure budgets over Korean corporate ledgers | Complete. [paper.pdf](./p3-leakage-quantification/paper.pdf) · reproduction: [`research/p3_leakage/`](../research/p3_leakage/) |
| [P4](./p4-admission-control/paper.md) | Admission Control for Probabilistic Callers | Complete. [paper.pdf](./p4-admission-control/paper.pdf) · reproduction: [`research/p4_admission/`](../research/p4_admission/) |

Reading order: P2 first (it defines the adversaries, the disclosure boundary and the
leakage decomposition everything else uses), then P3 and P4 in either order — P3
quantifies the host/user leakage channels on a realistic corpus, P4 quantifies and
contains the admission-control side against an adversary that can steer the query
planner itself.

## License

Papers and this documentation are licensed under
[CC BY 4.0](./LICENSE-CC-BY-4.0). Code under [`research/`](../research/) and
[`tokenis/`](../tokenis/) is licensed under [Apache-2.0](../LICENSE).
