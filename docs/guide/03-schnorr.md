# Schnorr Signatures and BIP340

This chapter explains Schnorr signatures: how they work, why BIP340 specifies
them for Bitcoin, and, critically, why their *linearity* makes threshold
signatures possible.

## The Schnorr Signature Equation

A Schnorr signature proves you know a private key x without revealing it.
The signer has:
- Private key x (a scalar in Z_Q)
- Public key P = x·G (a point on the curve)

To sign a message m:

1. Pick a random nonce k ← Z_Q
2. Compute the nonce commitment R = k·G
3. Compute the challenge e = H(R, P, m) (a hash binding the nonce, key, and message)
4. Compute the signature scalar s = k + e·x

The signature is the pair (R, s).

## Verification

The verifier has (P, m, R, s) and checks:

    s·G == R + e·P

Why does this work? Substitute s = k + e·x:

    (k + e·x)·G = k·G + e·x·G = R + e·P  ✓

The verifier never learns k or x. They only see R (which hides k behind the
discrete log) and s (which mixes k and x in a way that can't be separated
without knowing one of them).

## Why Schnorr: The Linearity Property

This is THE key insight for FROST. Schnorr signatures are *linear*: the
signature equation is a sum of scalar products, and scalar multiplication
distributes over addition.

Suppose two signers independently compute:
- s₁ = k₁ + e·x₁
- s₂ = k₂ + e·x₂

Their sum is:
- s₁ + s₂ = (k₁ + k₂) + e·(x₁ + x₂)

Verify against the combined key P₁ + P₂:
- (s₁ + s₂)·G = (k₁ + k₂)·G + e·(x₁ + x₂)·G = (R₁ + R₂) + e·(P₁ + P₂)

The partial signatures *add up* to a valid signature under the *sum* of the
public keys. This is what makes threshold Schnorr possible: each participant
contributes a partial signature, and the aggregator sums them into a valid
complete signature.

ECDSA (the signature scheme Bitcoin used before Taproot) does NOT have this
linearity property, which is why threshold ECDSA is significantly more complex.

## BIP340: Schnorr for Bitcoin

BIP340 specifies exactly how Schnorr signatures are used in Bitcoin. It makes
several choices that affect our FROST implementation:

### Tagged Hashes

BIP340 uses *tagged hashes* to prevent cross-protocol attacks. Instead of
bare SHA256, each hash is domain-separated:

    H_tag(msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)

The tag prefix is computed once and reused. Different operations use different
tags (e.g., "BIP0340/challenge" for the signature challenge). This ensures that
a hash value valid in one context cannot be repurposed in another.

See `tagged_hash.py` for the implementation:

```python
from frost.tagged_hash import tagged_hash

digest = tagged_hash("BIP0340/challenge", data)
```

### x-only Public Keys

As discussed in the previous chapter, BIP340 represents public keys by their
x-coordinate alone, always assuming even y. This means:

- Public keys are 32 bytes (not 33)
- Signatures include the x-coordinate of R (not the full point)
- The signer must negate their nonce or key when the natural y-coordinate
  would be odd

In FROST, this means extra negation logic in the signing protocol: both the
group nonce commitment R and the group public key Y must have even y for
BIP340 compatibility. The signing module handles these adjustments.

### The Challenge Hash

The BIP340 challenge is:

    e = H("BIP0340/challenge", R_x || P_x || m) mod Q

where R_x and P_x are the 32-byte x-coordinates of the nonce commitment and
public key, and m is the message.

```python
from frost.aggregator import Aggregator

e = Aggregator.challenge_hash(R, P, message)
```

## Nonce Reuse: Why It's Fatal

The Schnorr equation s = k + e·x is linear in both k and x. If a signer
reuses the same nonce k for two different messages:

- s₁ = k + e₁·x
- s₂ = k + e₂·x

An attacker who sees both signatures can subtract:

- s₁ - s₂ = (e₁ - e₂)·x
- x = (s₁ - s₂) / (e₁ - e₂)

The private key is recovered with simple scalar arithmetic. This is not a
theoretical concern: it has happened in practice (the PlayStation 3 ECDSA
key extraction used this exact attack with a *constant* nonce).

For FROST, this motivates two design decisions:
1. **Fresh nonces per signing session**: each participant generates a new
   random nonce pair for every signing operation.
2. **Binding values**: FROST adds a "binding value" ρᵢ that ties each
   participant's nonce to the specific message and signer set, preventing
   an attacker from manipulating nonce contributions across sessions.

## From Single Signer to Threshold

The linearity property shows that partial signatures can be summed. But in
FROST, participants don't each hold an independent key. Instead, they hold
*shares* of a single group key, distributed via Shamir's Secret Sharing.

The connection works like this:
- The group secret x is the constant term of a polynomial: x = f(0)
- Each participant i holds a share sᵢ = f(i)
- Lagrange interpolation recovers f(0) = ∑(λᵢ·sᵢ) for any t participants
- Therefore x·G = ∑(λᵢ·sᵢ)·G = ∑(λᵢ·sᵢ·G)

Each participant can compute λᵢ·sᵢ·c (their weighted share times the
challenge) without knowing x. The sum of these partial signatures, combined
with the sum of nonce contributions, yields a valid Schnorr signature under
the group public key.

This is the bridge from Schnorr to FROST. The next two chapters fill in the
missing pieces: how polynomial secret sharing works (Chapter 4) and how to
make it verifiable (Chapter 5).

## Summary

| Concept | Equation | Significance |
|---------|----------|-------------|
| Schnorr signing | s = k + e·x | Linear in both k and x |
| Verification | s·G = R + e·P | Public verification without secrets |
| Linearity | (s₁+s₂)·G = (R₁+R₂) + e·(P₁+P₂) | Enables threshold aggregation |
| BIP340 challenge | e = H("BIP0340/challenge", R_x \|\| P_x \|\| m) | Domain-separated, x-only |
| Nonce reuse | x = (s₁-s₂)/(e₁-e₂) | Fatal: reveals private key |
