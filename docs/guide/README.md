# FROST-BIP340 Companion Guide

A structured walkthrough of threshold Schnorr signatures, from finite fields
through FROST signing.

## Reading Order

1. [Introduction](01-introduction.md) — what FROST is and why it matters
2. [Finite Fields and Elliptic Curves](02-finite-fields.md) — the math foundation
3. [Schnorr Signatures and BIP340](03-schnorr.md) — single-signer Schnorr
4. [Shamir's Secret Sharing](04-secret-sharing.md) — polynomial secret sharing
5. [Polynomial Commitments](05-commitments.md) — verifiable secret sharing
6. [FROST DKG](06-dkg.md) — distributed key generation
7. [FROST Signing](07-signing.md) — threshold signing protocol
8. [Advanced Operations](08-advanced.md) — repair, enrollment, threshold changes
9. [Architecture](09-architecture.md) — codebase design and navigation

## Prerequisites

- Python familiarity (classes, modules, basic types)
- Basic algebra (variables, equations, modular arithmetic helps but isn't required)

## Interactive Exploration

The [tutorial notebooks](../../notebooks/) track this guide's progression
with runnable code. The [experiment notebooks](../../notebooks/) explore
specific "what if" questions.
