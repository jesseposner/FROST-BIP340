# Introduction

## What Are Threshold Signatures?

In a standard digital signature scheme, one private key produces one signature.
If that key is lost, stolen, or compromised, there is no recovery and no
defense. Threshold signatures change this: a secret key is distributed among
*n* participants such that any *t* of them (the threshold) can collaborate to
produce a valid signature, but fewer than *t* learn nothing about the key.

No single participant ever holds the full secret. The key is never
reconstructed during signing. The resulting signature is indistinguishable
from a standard single-signer signature.

## Why Threshold Signatures Matter for Bitcoin

Bitcoin's security model centers on private key control. Threshold signatures
address several practical problems:

- **Multisig custody**: A 3-of-5 threshold scheme protects funds even if two
  keys are compromised. Unlike Bitcoin's native multisig (which uses separate
  signatures and reveals the spending policy on-chain), threshold signatures
  produce a single standard signature.
- **Federation signing**: Multiple parties (exchanges, custodians, governance
  bodies) can jointly authorize transactions without trusting any single member.
- **Key resilience**: Lost or destroyed keys can be recovered through share
  repair without changing the group's public key.

## FROST in One Paragraph

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a threshold
signing protocol built on Schnorr signatures. Participants run a Distributed
Key Generation (DKG) protocol to jointly create a shared secret key, with each
participant receiving a secret share. When *t* participants want to sign, they
execute a two-round protocol: first publishing nonce commitments, then
computing signature shares that are aggregated into a single valid BIP340
Schnorr signature. No trusted dealer is needed, and the protocol is secure
against malicious participants (as long as fewer than *t* collude).

## What Makes This Implementation Educational

This codebase is designed for learning, not production. Four properties make it
distinct:

**First principles.** The secp256k1 curve primitives (scalar field arithmetic,
point addition, scalar multiplication) are built from scratch in `scalar.py`
and `point.py`. There are no calls to external cryptographic libraries. You can
trace every operation from the signing equation down to modular arithmetic.

**Self-contained.** The entire implementation has zero external dependencies for
core cryptography. The only external packages are development tools: pytest for
testing and Hypothesis for property-based tests. Everything you need to
understand FROST is in the source tree.

**BIP340-native.** All naming follows Bitcoin conventions: tagged hashes,
x-only public keys, even-y normalization. The code speaks the same language as
the BIP340 specification and Bitcoin Core's secp256k1 library, making it a
direct bridge from FROST theory to Bitcoin practice.

**Modular.** Each protocol phase lives in its own focused module: `keygen.py`
for distributed key generation, `signing.py` for the two-round signing
protocol, `repair.py` for share repair and enrollment, `threshold.py` for
threshold changes. The `Participant` class is a thin facade that composes these
modules. To understand any phase, read one file.

## How to Use This Guide

The chapters build on each other in sequence:

1. **Finite fields and elliptic curves** establish the mathematical foundation.
2. **Schnorr signatures** show how single-signer signing works, and critically,
   why the linearity of Schnorr signatures enables threshold schemes.
3. **Shamir's Secret Sharing** introduces polynomial secret sharing.
4. **Polynomial commitments** add verifiability to secret sharing.
5. **FROST DKG** combines these pieces into distributed key generation.
6. **FROST signing** walks through the threshold signing protocol.
7. **Advanced operations** cover share repair, enrollment, and threshold changes.
8. **Architecture** maps the conceptual pieces to the codebase.

Each chapter explains the concepts first, then references the relevant source
module for implementation details. Small inline code snippets illustrate key
ideas, but the guide is designed to be readable without running any code.

For hands-on exploration, the [tutorial notebooks](../../notebooks/) track this
guide's progression with runnable code, and the
[experiment notebooks](../../notebooks/) explore specific "what if" questions.

## What This Guide Does NOT Cover

This is an educational implementation. We deliberately omit production concerns:

- **Constant-time operations**: Real implementations must avoid timing
  side-channels in scalar and field arithmetic.
- **Side-channel resistance**: Power analysis, electromagnetic emanation, and
  cache-timing attacks require specialized countermeasures.
- **Projective/Jacobian coordinates**: Our point arithmetic uses affine
  coordinates (with a modular inversion per addition). Production libraries use
  projective coordinates to batch inversions.
- **Hardware acceleration**: Production libraries exploit CPU-specific
  instructions and precomputed endomorphism tables.

For production FROST implementations, see
[ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) (Rust) or
the frost module in secp256k1-zkp.
