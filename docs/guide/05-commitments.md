# Polynomial Commitments

This chapter bridges Shamir's Secret Sharing to FROST's Distributed Key
Generation. The key problem: in a decentralized setting, how do you verify
that a share is correct without seeing the polynomial that generated it?

## The Problem

In Shamir's Secret Sharing as described in the previous chapter, a single
dealer generates the polynomial and distributes shares. Recipients must trust
the dealer:
- Did the dealer actually evaluate the polynomial honestly?
- Did every participant receive a share from the same polynomial?
- Does the dealer even know the secret they committed to?

In FROST's DKG, there is no trusted dealer. Every participant generates their
own polynomial and distributes shares to every other participant. Each
participant needs to verify the shares they receive, without seeing anyone
else's polynomial coefficients.

## Coefficient Commitments

The solution uses a core property of elliptic curves: scalar multiplication
is a *one-way homomorphism*.

Given a coefficient aⱼ, publish its commitment:

    Aⱼ = aⱼ·G

This commitment *hides* aⱼ (recovering aⱼ from Aⱼ requires solving the
discrete logarithm, which is computationally infeasible) while allowing
public verification of relationships involving aⱼ.

```python
from frost.keygen import compute_coefficient_commitments

commitments = compute_coefficient_commitments(coefficients)
# commitments[j] = coefficients[j] · G
```

A participant publishes one commitment per coefficient: (A₀, A₁, ..., A_{t-1}).
The first commitment A₀ = a₀·G is particularly important: it's the public
commitment to the participant's secret.

## Share Verification

Here's where the homomorphism pays off. If the share sᵢ = f(i) was computed
honestly from the polynomial f(x) = a₀ + a₁·x + … + a_{t-1}·x^{t-1}, then:

    sᵢ·G = f(i)·G = (a₀ + a₁·i + a₂·i² + … + a_{t-1}·i^{t-1})·G

Because scalar multiplication distributes over addition:

    sᵢ·G = a₀·G + a₁·i·G + a₂·i²·G + … = A₀ + i·A₁ + i²·A₂ + …

The right side uses only the *public* commitments (Aⱼ) and the participant's
index (i). So anyone can compute what sᵢ·G *should* be using only public
information, then check whether the received share matches.

The verification check:

    sᵢ·G == ∑(i^k · Aₖ) for k = 0..t-1

```python
from frost.keygen import verify_share

is_valid = verify_share(share, participant_index, coefficient_commitments)
```

If this check passes, the share is consistent with the published commitments.
If it fails, the dealer is cheating.

This scheme is known as **Feldman's Verifiable Secret Sharing** (Feldman,
"A Practical Scheme for Non-interactive Verifiable Secret Sharing," 28th
FOCS, pp. 427-438, IEEE, 1987). It extends Shamir's Secret Sharing by
publishing commitments that let recipients verify their shares without a
trusted dealer. FROST uses Feldman's VSS as the verification layer during
DKG.

*Naming note:* Some literature calls these "Pedersen commitments," but
Pedersen's scheme (CRYPTO '91) uses *two* generators. The single-generator
construction Aⱼ = aⱼ·G used here is Feldman's.

## Why This Works: The Homomorphism

The key mathematical property is:

    (a + b)·G = a·G + b·G

Scalar multiplication "commutes" with addition. This means you can verify
*relationships between secrets* by checking the corresponding relationships
*between their public commitments*, without ever learning the secrets
themselves.

This single property enables:
- Share verification (this chapter)
- Public key derivation from individual commitments (DKG)
- Signature share verification (signing)
- Repair share verification (share repair)

## Proof of Knowledge

Commitments alone prove that shares are consistent with *some* polynomial,
but they don't prove the committer actually *knows* the secret (the constant
term a₀). A malicious participant could publish commitments copied from
another participant.

A *proof of knowledge* solves this. It's a Schnorr signature of knowledge:
the participant proves they know the discrete log of A₀ = a₀·G without
revealing a₀:

1. Pick random nonce k, publish R = k·G
2. Compute challenge c = H(index, context, A₀, R)
3. Compute response μ = k + a₀·c

The verifier checks: μ·G == R + c·A₀

This is the same Schnorr equation from Chapter 3, applied as a proof of
knowledge rather than a signature on a message. The challenge binds the
prover's identity (index) to prevent replaying proofs across participants.

```python
from frost.keygen import compute_proof_of_knowledge, verify_proof_of_knowledge

proof = compute_proof_of_knowledge(secret, index)
is_valid = verify_proof_of_knowledge(proof, secret_commitment, index)
```

## Bridge to DKG

With these three building blocks, we have everything needed for trustless
distributed key generation:

1. **Polynomial commitments**: each participant publishes Aⱼ = aⱼ·G for
   their polynomial coefficients, hiding the coefficients while enabling
   public verification.

2. **Share verification**: each recipient checks that their received share
   is consistent with the sender's published commitments, catching any
   dishonest participant.

3. **Proof of knowledge**: each participant proves they actually know the
   secret behind their commitment, preventing commitment copying.

The next chapter puts these pieces together into FROST's Distributed Key
Generation protocol.

## Summary

| Concept | Code reference | Purpose |
|---------|---------------|---------|
| Coefficient commitment | `keygen.compute_coefficient_commitments()` | Publish Aⱼ = aⱼ·G |
| Share verification | `keygen.verify_share()` | Check sᵢ·G == ∑(i^k·Aₖ) |
| Proof of knowledge | `keygen.compute_proof_of_knowledge()` | Prove knowledge of a₀ |
| Verify proof | `keygen.verify_proof_of_knowledge()` | Check Schnorr proof |
