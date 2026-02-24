# FROST-BIP340

Educational reference implementation of FROST threshold Schnorr signatures
for secp256k1/BIP340.

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) enables t-of-n
participants to collaboratively produce a valid Schnorr signature without ever
reconstructing the shared secret key. This implementation is built from first
principles: secp256k1 field arithmetic, curve point operations, and polynomial
secret sharing are all self-contained with zero external crypto dependencies.
All naming follows BIP340/Bitcoin conventions throughout.

## Quick Start

```bash
uv sync                        # install dependencies
uv run python -m pytest        # run tests (85 tests, ~36s)
```

A 2-of-3 threshold signing ceremony:

```python
from frost import Participant, Aggregator, Point

# --- DKG: Distributed Key Generation ---
threshold, n = 2, 3
participants = [Participant(index=i, threshold=threshold, participants=n) for i in range(1, n + 1)]

for p in participants:
    p.init_keygen()
    p.generate_shares()

for receiver in participants:
    other_shares = tuple(
        sender.shares[receiver.index - 1]
        for sender in participants if sender.index != receiver.index
    )
    receiver.aggregate_shares(other_shares)

for p in participants:
    other_commitments = tuple(
        other.coefficient_commitments[0]
        for other in participants if other.index != p.index
    )
    p.derive_public_key(other_commitments)

for p in participants:
    other_ccs = tuple(
        other.coefficient_commitments
        for other in participants if other.index != p.index
    )
    p.derive_group_commitments(other_ccs)

# --- Signing: any 2 of 3 ---
signers = [participants[0], participants[1]]
signer_indexes = tuple(p.index for p in signers)
message = b"Hello from FROST!"

for signer in signers:
    signer.generate_nonce_pair()

nonce_pairs = [None] * n
for signer in signers:
    nonce_pairs[signer.index - 1] = signer.nonce_commitment_pair
for i in range(n):
    if nonce_pairs[i] is None:
        nonce_pairs[i] = (Point(), Point())
nonce_commitment_pairs = tuple(nonce_pairs)

shares = tuple(p.sign(message, nonce_commitment_pairs, signer_indexes) for p in signers)

aggregator = Aggregator(
    signers[0].public_key, message,
    nonce_commitment_pairs, signer_indexes,
    group_commitments=participants[0].group_commitments,
)
signature = aggregator.signature(shares)
print(f"BIP340 signature: {signature}")
```

The output is a standard 64-byte BIP340 Schnorr signature, indistinguishable
from a single-signer signature.

## Learn

Three layers, each building on the last:

**[Companion Guide](docs/guide/)** -- structured walkthrough from finite fields
through FROST signing (9 chapters).

**Tutorial Notebooks** -- interactive step-by-step, tracking the guide:

| Notebook | Topic |
|----------|-------|
| [tutorial-01](notebooks/tutorial-01-scalars.ipynb) | Scalars and the finite field |
| [tutorial-02](notebooks/tutorial-02-points.ipynb) | Points on the curve |
| [tutorial-03](notebooks/tutorial-03-schnorr.ipynb) | Schnorr signatures (BIP340) |
| [tutorial-04](notebooks/tutorial-04-secret-sharing.ipynb) | Secret sharing with polynomials |
| [tutorial-05](notebooks/tutorial-05-dkg.ipynb) | Running a DKG ceremony |
| [tutorial-06](notebooks/tutorial-06-signing.ipynb) | Signing with FROST |

**Experiment Notebooks** -- "what if" deep dives for readers with context:

| Notebook | Question |
|----------|----------|
| [experiment-01](notebooks/experiment-01-scalar-axioms.ipynb) | Does our field satisfy the axioms? |
| [experiment-02](notebooks/experiment-02-corrupted-shares.ipynb) | What happens with corrupted shares? |
| [experiment-03](notebooks/experiment-03-signing-order.ipynb) | Does signing order matter? |
| [experiment-04](notebooks/experiment-04-share-repair.ipynb) | How does share repair work? |
| [experiment-05](notebooks/experiment-05-enrollment.ipynb) | How do you add/remove participants? |
| [experiment-06](notebooks/experiment-06-threshold-changes.ipynb) | Can you change the threshold? |
| [experiment-07](notebooks/experiment-07-performance.ipynb) | How fast is pure Python crypto? |

## Modules

| Module | Description |
|--------|-------------|
| `frost.scalar` | Scalar field arithmetic (Z_Q) |
| `frost.point` | secp256k1 curve point operations |
| `frost.constants` | Curve constants (P, Q, G coordinates) |
| `frost.tagged_hash` | BIP340 tagged hash utility |
| `frost.polynomial` | Polynomial generation and evaluation |
| `frost.lagrange` | Lagrange interpolation coefficients |
| `frost.matrix` | Matrix operations for threshold changes |
| `frost.keygen` | Distributed Key Generation (DKG) |
| `frost.signing` | FROST two-round signing protocol |
| `frost.aggregator` | Signature aggregation and share verification |
| `frost.repair` | Share repair and enrollment |
| `frost.threshold` | Threshold increase and decrease |

The `Participant` class provides a stateful facade over the protocol modules.
For learning, read the modules directly.

## Tests

85 tests covering protocol correctness and edge cases:

- DKG ceremonies, signing, repair, enrollment, threshold changes
- Property-based tests (Hypothesis) for 7 protocol invariants: roundtrip
  serialization, threshold reconstruction, signature validity, share
  verification, signing commutativity, repair correctness, enrollment safety
- Error path tests for parameter validation and missing state

```bash
uv run python -m pytest -v       # verbose output
uv run python -m pytest -k sign  # just signing tests
```

## Background

- [Brink blog: Jesse Posner on FROST](https://brink.dev/blog/2021/04/15/frost/)
- [Introductory slides](FROST.pdf)
- [FROST flow diagram](dot/api/frost.pdf)

## Requirements

Python 3.13+. No external dependencies for core crypto. Dev dependencies
(pytest, Hypothesis, ruff, ty) are managed by [uv](https://docs.astral.sh/uv/).

## Disclaimer

This is an educational implementation. It is NOT suitable for production use:
no constant-time operations, no side-channel resistance, pure Python
performance. For production FROST, see
[ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) (Rust) or
[secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp).

---

This work is made possible with the support of [Brink](https://brink.dev).
