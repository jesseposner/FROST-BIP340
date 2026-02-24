# FROST Signing

After DKG, each participant holds an aggregate share sᵢ of the group secret,
and the group has a public key Y. Now a subset of t signers collaborates to
produce a BIP340 Schnorr signature on a message, without ever reconstructing
the secret.

The result is a standard 64-byte BIP340 signature, indistinguishable from one
produced by a single signer. No observer can tell that multiple parties
collaborated.

## The Two-Round Protocol

FROST signing is structured as two rounds of communication. Round 1 commits
each signer to a nonce. Round 2 uses those commitments to compute signature
shares that combine into the final signature.

### Round 1: Nonce Commitments

Each signer generates a *pair* of random nonces (dᵢ, eᵢ) and publishes
their commitments (Dᵢ, Eᵢ) = (dᵢ·G, eᵢ·G).

```python
from frost.signing import generate_nonce_pair

(nonce_pair, commitment_pair) = generate_nonce_pair()
# nonce_pair = (d, e), commitment_pair = (D, E)
```

Why two nonces instead of one? A single nonce would allow a malicious
aggregator to manipulate the group commitment. By introducing a second nonce
weighted by a binding value (computed from the full set of commitments), each
signer's contribution becomes locked to the specific signing session. This
eliminates a class of attacks where the aggregator selectively combines
commitments to extract information about honest signers' shares.

Nonce pairs are single-use. Reusing a nonce pair across different signing
sessions leaks the signer's secret share, because an attacker can set up a
system of equations and solve for sᵢ.

### Binding Values

Once all commitment pairs are collected, each signer's binding value is
computed:

    ρᵢ = H(i, m, B)

where i is the signer's index, m is the message, and B is the list of all
nonce commitment pairs from all signers. This binds each participant's nonce
contribution to the specific message *and* the specific set of commitments.

If any signer changes their commitment after seeing others' commitments, or if
the aggregator tries to substitute a commitment, the binding values change and
the protocol produces an invalid signature.

### The Group Commitment

The group nonce commitment R is assembled from all signers' contributions:

    R = ∑(Dᵢ + ρᵢ·Eᵢ) for all signers i

Each signer contributes their first nonce commitment Dᵢ plus their binding-
weighted second nonce commitment ρᵢ·Eᵢ. The binding values ensure that each
contribution is fixed relative to the full set.

```python
from frost.aggregator import Aggregator

R = Aggregator.group_commitment(message, nonce_commitment_pairs, participant_indexes)
```

### The Challenge Hash

The BIP340 challenge is computed exactly as in single-signer Schnorr (Chapter 3):

    c = H("BIP0340/challenge", R_x ‖ Y_x ‖ m)

Same tagged hash, same inputs. This is what makes the final signature
indistinguishable from a single-signer signature: the verifier sees only
(R, z) and checks the same equation.

### Round 2: Signature Shares

Each signer computes their signature share using the FROST signing equation:

    zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c

Where:
- dᵢ, eᵢ: the nonce pair (secret, single-use)
- ρᵢ: the binding value (public, computed from commitments)
- λᵢ: the Lagrange coefficient for this signer in the signing group (Chapter 4)
- sᵢ: the signer's aggregate share (secret, from DKG)
- c: the BIP340 challenge hash (public)

```python
from frost.signing import sign

z_i = sign(
    nonce_pair, aggregate_share, public_key,
    participant_index, message,
    nonce_commitment_pairs, participant_indexes,
)
```

## Why the Equation Works

The magic is in the Lagrange coefficients. When all signature shares are summed:

    z = ∑(zᵢ) = ∑(dᵢ + eᵢ·ρᵢ) + ∑(λᵢ·sᵢ)·c

The first sum ∑(dᵢ + eᵢ·ρᵢ) is the discrete log of R (the group nonce
commitment). Call it k.

The second sum ∑(λᵢ·sᵢ) is Lagrange interpolation of the aggregate shares
at x=0. From Chapter 4, this recovers the group secret y.

So the aggregate equation is:

    z = k + y·c

This is exactly the standard Schnorr signing equation from Chapter 3. The
threshold protocol produces the same algebraic result as single-signer Schnorr,
without any party knowing k (the group nonce) or y (the group secret).

## BIP340 Adjustments

BIP340 uses x-only public keys, which requires that both the nonce point R and
the public key Y have even y-coordinates. FROST handles this with parity
adjustments:

- If R has odd y: each signer negates their nonces (dᵢ, eᵢ → -dᵢ, -eᵢ)
- If Y has odd y: each signer negates their aggregate share (sᵢ → -sᵢ)

These negations are applied before computing the signature share. The effect is
equivalent to single-signer BIP340's convention of negating the private key or
nonce as needed.

### Why Negation Works

The BIP340 verifier checks: `s·G = R + e·P` where `P` has even y.

If the group key `P` has odd y, we use `-P` (even y) as the public key. The
group secret is effectively `-s` instead of `s`. Each participant must negate
their share `sᵢ` so the partial signatures sum correctly:

    Σ(-sᵢ·λᵢ) = -s = the effective secret for -P

The same logic applies to nonces: if the group nonce `R` has odd y, each signer
negates their nonce components so the partial nonces sum to `-R` (which has
even y). The verification equation is preserved because both sides are negated
consistently.

## Aggregation

The aggregator collects all signature shares and sums them:

    z = ∑(zᵢ) mod Q

The final BIP340 signature is (R_x, z): the x-coordinate of the group
commitment concatenated with the aggregate response. This is a standard 64-byte
Schnorr signature.

```python
agg = Aggregator(public_key, message, nonce_commitment_pairs, participant_indexes)
signature_hex = agg.signature(signature_shares)
```

## Signature Share Verification

Before aggregating, the aggregator can (and should) verify each individual
share. If a single signer submits a bad share, the aggregate signature will be
invalid, and without per-share verification there's no way to identify the
culprit.

The verification equation for signer i:

    zᵢ·G == Rᵢ + c·λᵢ·Yᵢ

where Rᵢ is the signer's adjusted nonce contribution (Dᵢ + ρᵢ·Eᵢ, negated if
R has odd y), and Yᵢ is their public verification share (from the group
commitments, adjusted for key parity).

This works because if zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c, then:

    zᵢ·G = (dᵢ + eᵢ·ρᵢ)·G + (λᵢ·sᵢ·c)·G = Rᵢ + c·λᵢ·Yᵢ

```python
Aggregator.verify_signature_share(
    share, participant_index, participant_indexes,
    group_commitment, public_key,
    nonce_commitment_pairs, message,
    public_verification_share,
)
```

When the `Aggregator` is constructed with `group_commitments`, it automatically
verifies every share before aggregation and raises an error identifying the
misbehaving signer.

## Key Tweaking

BIP32 derivation and taproot spending modify the effective public key through
additive tweaks. FROST supports this by adjusting the signing equation to
account for the tweak value.

The signing and aggregation functions accept optional `bip32_tweak` and
`taproot_tweak` parameters. When provided, the challenge hash is computed
against the tweaked key, and the aggregate signature includes a correction term
so the result verifies against the tweaked public key. This enables FROST
signatures that are compatible with BIP32 HD wallets and taproot spending paths.

## The Full Picture

Putting both rounds together:

1. Signers publish nonce commitments (Dᵢ, Eᵢ)
2. Binding values ρᵢ lock each commitment to the session
3. The group commitment R and challenge c are derived
4. Each signer computes zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c
5. The aggregator verifies each share, then sums: z = ∑(zᵢ)
6. The output (R_x, z) is a standard BIP340 Schnorr signature

The Lagrange coefficients reconstruct the secret in the exponent. The binding
values prevent nonce manipulation. The BIP340 parity adjustments ensure
compatibility. The result: a threshold signature protocol that produces
standard Bitcoin signatures.

## Summary

| Concept | Code reference | Purpose |
|---------|---------------|---------|
| Nonce pair | `signing.generate_nonce_pair()` | (dᵢ, eᵢ) and (Dᵢ, Eᵢ) |
| Binding value | `Aggregator.binding_value()` | ρᵢ = H(i, m, B) |
| Group commitment | `Aggregator.group_commitment()` | R = ∑(Dᵢ + ρᵢ·Eᵢ) |
| Challenge hash | `Aggregator.challenge_hash()` | c = H(R, Y, m) |
| Signature share | `signing.sign()` | zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c |
| Share verification | `Aggregator.verify_signature_share()` | Catch bad signers |
| Aggregation | `Aggregator.signature()` | z = ∑(zᵢ), output (R, z) |
