# Architecture

After learning the protocol, this chapter zooms out to show how the codebase
is organized and how to navigate it independently.

## Module Dependency Graph

The codebase is layered. Lower modules know nothing about higher ones:

```
constants
  ├── scalar
  │     └── polynomial, lagrange
  └── point
        └── keygen, signing, repair, threshold
              └── aggregator
                    └── participant
```

Each protocol module (`keygen`, `signing`, `repair`, `threshold`) depends on
the primitive types (`Scalar`, `Point`) and utility modules (`polynomial`,
`lagrange`), but not on each other. You can read any protocol module in
isolation.

The `matrix` module (used by `threshold` for Vandermonde inversion) is the one
cross-cutting utility that doesn't fit neatly into the hierarchy. It operates
on scalars and points for coefficient commitment derivation.

## The Participant Class

`participant.py` (352 lines) is a state container and protocol orchestrator. It
holds a participant's state across all protocol phases: index, threshold,
coefficients, shares, keys, nonces, and repair data. Every cryptographic
operation delegates to the protocol modules:

```python
# Participant.init_keygen() calls:
polynomial.generate_polynomial()
keygen.compute_coefficient_commitments()
keygen.compute_proof_of_knowledge()
keygen.generate_shares()
```

The `Participant` class is useful for *using* the library: it manages the state
transitions between DKG, signing, repair, and threshold changes. But for
*learning* the protocol, read the individual modules directly. They contain
the algorithms, the equations, and the docstrings that explain each step.

## The Aggregator Class

`aggregator.py` (393 lines) coordinates the signing protocol. It computes
binding values, group commitments, and challenge hashes. When constructed with
group commitments, it verifies each individual signature share before
aggregating them into the final BIP340 signature.

The Aggregator also handles key tweaking for BIP32 derivation and taproot
compatibility.

## Design Decisions

**Free functions, not methods.** The protocol modules expose free functions
rather than methods on classes. `keygen.verify_share(share, index, commitments)`
is clearer and more testable than `participant.verify_share()`. The Participant
class composes these functions; it doesn't replace them.

**Value types for primitives.** `Scalar` wraps integers mod Q (the curve order)
with arithmetic operators. `Point` wraps secp256k1 curve points with addition
and scalar multiplication. These types make the protocol code read like the
mathematical equations it implements.

**No external dependencies.** All cryptography is built from first principles:
modular arithmetic, point addition, scalar multiplication, tagged hashes. This
means you can trace any operation from the signing equation down to field
arithmetic, with no opaque library calls in between.

**BIP340 throughout.** Tagged hashes (`H("BIP0340/challenge", ...)`), x-only
public keys, even-y normalization: these Bitcoin conventions are integrated at
every level of the code, not bolted on as an afterthought. The implementation
speaks the same language as the BIP340 specification.

## Two Ways to Use the Library

```python
# Direct module calls (for learning):
from frost.keygen import generate_shares, verify_share
from frost.signing import sign
from frost.aggregator import Aggregator

# Participant facade (for convenience):
from frost import Participant, Aggregator
p = Participant(index=1, threshold=2, participants=3)
p.init_keygen()
```

The direct approach is better for understanding: each function call maps to one
step of the protocol, with explicit inputs and outputs. The Participant approach
is better for usage: it tracks state so you don't have to.

## What This Implementation Is NOT

This is an educational implementation. It deliberately omits production concerns:

- **No constant-time operations.** Branching on secret values leaks timing
  information. Production implementations use constant-time field arithmetic.
- **No side-channel resistance.** Power analysis, cache timing, and
  electromagnetic attacks require specialized countermeasures.
- **Affine coordinates only.** Each point addition requires a modular inversion.
  Production libraries use projective or Jacobian coordinates to batch these.
- **Pure Python performance.** Roughly 1000x slower than C implementations
  like libsecp256k1. Adequate for testing and learning, not for signing
  transactions.

For production FROST: [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost)
(Rust) or the frost module in secp256k1-zkp (C).

## Where to Go Next

- **The FROST paper**: Komlo & Goldberg, "FROST: Flexible Round-Optimized
  Schnorr Threshold Signatures" (2020)
- **RFC 9591**: the IETF standardization of the FROST protocol
- **Tutorial notebooks** in this repo: hands-on walkthroughs that track this
  guide's progression
- **Experiment notebooks** in this repo: explorations of specific "what if"
  questions about the protocol
- **Production implementations**: ZcashFoundation/frost, secp256k1-zkp
