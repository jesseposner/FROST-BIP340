# FROST-BIP340

Educational reference implementation of FROST threshold Schnorr signatures
for secp256k1/BIP340.

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) enables t-of-n
participants to collaboratively produce a valid Schnorr signature without ever
reconstructing the shared secret key. This implementation is built from first
principles: secp256k1 field arithmetic, curve point operations, and polynomial
secret sharing are all self-contained with zero external crypto dependencies.
All naming follows BIP340/Bitcoin conventions throughout.

## Modules

| Module | Description |
|--------|-------------|
| `frost.scalar` | Scalar field arithmetic (Z_Q) |
| `frost.point` | secp256k1 curve point operations |
| `frost.polynomial` | Polynomial generation and evaluation |
| `frost.lagrange` | Lagrange interpolation coefficients |
| `frost.keygen` | Distributed Key Generation (DKG) |
| `frost.signing` | FROST two-round signing protocol |
| `frost.aggregator` | Signature aggregation and share verification |
| `frost.repair` | Share repair and enrollment |
| `frost.threshold` | Threshold increase and decrease |

The `Participant` class provides a stateful facade over these modules.
For learning, read the modules directly.

## Quick Start

```bash
uv run python -m pytest        # run tests
```

```python
from frost import Participant, Aggregator
```

## Learn More

- [Companion Guide](docs/guide/) — structured walkthrough from finite fields
  through FROST signing
- [Tutorial Notebooks](notebooks/) — interactive step-by-step explorations
- [Experiment Notebooks](notebooks/) — "what if" deep dives

## Background

- [Brink blog: Jesse Posner on FROST](https://brink.dev/blog/2021/04/15/frost/)
- [Introductory slides](FROST.pdf)
- [FROST flow diagram](dot/api/frost.pdf)

## Requirements

Python 3.10+. No external dependencies for core crypto.

## Disclaimer

This is an educational implementation. It is NOT suitable for production use:
no constant-time operations, no side-channel resistance, pure Python
performance. For production FROST, see ZcashFoundation/frost (Rust) or
secp256k1-zkp.

---

This work is made possible with the support of [Brink](https://brink.dev).
