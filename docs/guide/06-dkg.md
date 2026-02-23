# FROST Distributed Key Generation

This is the payoff chapter. Every building block from the previous four
chapters, polynomials, shares, commitments, proofs of knowledge, comes together
into a single protocol that lets a group of participants jointly create a shared
secret key without trusting anyone.

## DKG as Parallel, Verified Shamir

Recall Shamir's Secret Sharing from Chapter 4: a single dealer picks a
polynomial, evaluates it at each participant's index, and hands out the shares.
The dealer knows the secret and must be trusted to behave honestly.

FROST's DKG eliminates the dealer. Instead, *every participant runs their own
Shamir's scheme simultaneously*. Each participant:

1. Generates their own random polynomial
2. Publishes commitments to their coefficients (Chapter 5)
3. Proves knowledge of their secret term (Chapter 5)
4. Sends polynomial evaluations to every other participant
5. Verifies received shares against the sender's commitments

The group secret is the sum of all participants' individual secrets: y = ∑(a₀ⱼ)
for all participants j. No single participant knows y, because no one knows
anyone else's constant term. Yet any t aggregate shares can reconstruct y via
Lagrange interpolation, exactly as in single-dealer Shamir.

## The DKG Ceremony

Let's trace through a concrete 2-of-3 example with Alice (index 1), Bob
(index 2), and Carol (index 3). The threshold is t = 2, so each participant
generates a degree-1 polynomial (a line).

### Step 1: Polynomial Generation

Each participant generates a random polynomial of degree t-1 = 1. The constant
term is their secret.

- Alice: f_A(x) = a₀ + a₁·x
- Bob:   f_B(x) = b₀ + b₁·x
- Carol: f_C(x) = c₀ + c₁·x

```python
from frost.polynomial import generate_polynomial

coefficients = generate_polynomial(threshold=2)
# coefficients = (secret, random_coefficient)
```

Each participant keeps their coefficients private. The constant terms a₀, b₀, c₀
are the individual secrets that will sum to form the group secret.

### Step 2: Commitment and Proof

Each participant publishes two things:

**Coefficient commitments**: Aⱼ = aⱼ·G for each coefficient. These hide the
coefficients while enabling verification (exactly the Pedersen commitments
from Chapter 5).

**Proof of knowledge**: a Schnorr proof that they know their secret a₀, the
discrete log of their first commitment A₀. This prevents a malicious
participant from copying someone else's commitments.

```python
from frost.keygen import compute_coefficient_commitments, compute_proof_of_knowledge

commitments = compute_coefficient_commitments(coefficients)
proof = compute_proof_of_knowledge(secret=coefficients[0], index=1)
```

After this step, every participant has broadcast their commitment list and
proof to all others. Nothing secret has been revealed: the commitments hide
the coefficients, and the proof reveals nothing beyond the fact that the
prover knows their secret.

### Step 3: Proof Verification

Before proceeding, each participant verifies every other participant's proof of
knowledge. If Alice receives Bob's proof and commitment A₀_Bob, she checks:

    μ·G == R + c·A₀_Bob

This is the same Schnorr verification equation from Chapter 5. If any proof
fails, the protocol aborts: that participant is either malfunctioning or
malicious.

```python
from frost.keygen import verify_proof_of_knowledge

assert verify_proof_of_knowledge(proof, commitments[0], sender_index)
```

### Step 4: Share Distribution

Each participant evaluates their polynomial at every other participant's index
and sends the result privately.

Alice computes:
- f_A(1) = a₀ + a₁·1 (keeps this, her self-share)
- f_A(2) = a₀ + a₁·2 (sends to Bob)
- f_A(3) = a₀ + a₁·3 (sends to Carol)

Bob and Carol do the same with their polynomials.

```python
from frost.keygen import generate_shares

shares = generate_shares(coefficients, num_participants=3)
# shares[0] = f(1), shares[1] = f(2), shares[2] = f(3)
```

After this step, each participant holds one share from every other participant
(plus their own self-share): three shares total for each participant.

### Step 5: Share Verification

Each recipient verifies their received share against the sender's published
commitments. When Bob receives f_A(2) from Alice, he checks:

    f_A(2)·G == A₀ + 2·A₁

This is the share verification equation from Chapter 5, using Alice's published
commitments. If it fails, Alice sent a bad share.

```python
from frost.keygen import verify_share

assert verify_share(received_share, my_index, sender_commitments)
```

This step is what makes the DKG *verifiable*. In single-dealer Shamir, you had
to trust the dealer. Here, every share is checked against public commitments.
A cheating participant is caught immediately.

### Step 6: Share Aggregation

Each participant sums all received shares (including their self-share) to get
their aggregate share sᵢ.

Alice's aggregate share:

    s₁ = f_A(1) + f_B(1) + f_C(1)

Bob's aggregate share:

    s₂ = f_A(2) + f_B(2) + f_C(2)

Carol's aggregate share:

    s₃ = f_A(3) + f_B(3) + f_C(3)

```python
from frost.keygen import aggregate_shares

aggregate = aggregate_shares(own_share, other_shares)
```

Each aggregate share sᵢ is a point on a "virtual" group polynomial F(x) =
∑(fⱼ(x)) whose constant term is the group secret y = ∑(a₀ⱼ). No one computed
F(x) directly, but each participant holds an evaluation of it at their index.

### Step 7: Public Key Derivation

The group public key is the sum of all participants' secret commitments (the
A₀ values):

    Y = A₀_Alice + A₀_Bob + A₀_Carol = ∑(A₀ⱼ)

Because scalar multiplication distributes over addition:

    Y = a₀_A·G + a₀_B·G + a₀_C·G = (a₀_A + a₀_B + a₀_C)·G = y·G

So Y is the public key corresponding to the group secret y, but no one knows y.

```python
from frost.keygen import derive_public_key

public_key = derive_public_key(own_commitment, other_commitments)
```

## Why This Works

The critical insight is that summing polynomials produces a new polynomial:

    F(x) = f_A(x) + f_B(x) + f_C(x)

This group polynomial F has:
- Constant term: F(0) = a₀ + b₀ + c₀ = y (the group secret)
- Degree: t-1 (same as each individual polynomial)

Each participant's aggregate share sᵢ = F(i) is a point on F. So any t
aggregate shares can reconstruct F(0) = y via Lagrange interpolation, but
fewer than t shares leave the secret completely undetermined (the same
information-theoretic security from Chapter 4).

The group secret y was never computed by anyone. It exists only implicitly, as
the sum of individual secrets that remain private to each participant. Yet the
group can use it for signing, because FROST's signing protocol works with
shares directly (Chapter 7).

## Group Commitments

Beyond the public key Y, the DKG produces another important public value: the
group commitments. These are the element-wise sum of all participants'
coefficient commitments:

    C₀ = A₀_Alice + A₀_Bob + A₀_Carol  (= Y, the public key)
    C₁ = A₁_Alice + A₁_Bob + A₁_Carol

For a threshold t, there are t group commitments (C₀, C₁, ..., C_{t-1}).
They encode the "shape" of the group polynomial in public form: Cⱼ = ∑(aⱼₖ)·G
for all participants k.

```python
from frost.keygen import derive_group_commitments

group_commitments = derive_group_commitments(own_cc, other_ccs)
```

## Public Verification Shares

Each participant's public verification share is Yᵢ = sᵢ·G. This is the public
counterpart of their aggregate share: it proves they hold a valid share without
revealing the share itself.

The key property: Yᵢ can be derived from the group commitments *without knowing
sᵢ*. The derivation uses the same commitment verification equation from
Chapter 5, applied to the group commitments:

    Yᵢ = ∑(i^k · Cₖ) for k = 0..t-1

where Cₖ are the group commitments. This works because:

    sᵢ·G = F(i)·G = ∑(i^k · Fₖ)·G = ∑(i^k · Cₖ)

So anyone with the group commitments can compute what any participant's public
verification share *should* be, and compare it against sᵢ·G to verify
correctness.

```python
from frost.keygen import public_verification_share, derive_public_verification_share

Yi_direct = public_verification_share(aggregate_share)
Yi_derived = derive_public_verification_share(group_commitments, index)
assert Yi_direct == Yi_derived
```

Public verification shares serve two purposes:
1. **During signing**: the aggregator uses them to verify individual signature
   shares (Chapter 7)
2. **During repair**: they anchor the repair protocol's verification checks
   (Chapter 8)

## What Each Participant Holds After DKG

| Item | Symbol | Visibility |
|------|--------|------------|
| Aggregate share | sᵢ | Private (secret) |
| Public key | Y | Public |
| Group commitments | (C₀, C₁, ...) | Public |
| Public verification share | Yᵢ = sᵢ·G | Public (derivable) |
| Participant index | i | Public |
| Threshold | t | Public |

The aggregate share sᵢ is the only secret. Everything else is either public
or derivable from public information. This is all a participant needs to
participate in signing (Chapter 7).

## Summary

| Concept | Code reference | Purpose |
|---------|---------------|---------|
| Polynomial generation | `polynomial.generate_polynomial()` | Random degree-(t-1) polynomial |
| Coefficient commitments | `keygen.compute_coefficient_commitments()` | Publish Aⱼ = aⱼ·G |
| Proof of knowledge | `keygen.compute_proof_of_knowledge()` | Prove knowledge of a₀ |
| Share generation | `keygen.generate_shares()` | Evaluate polynomial at each index |
| Share verification | `keygen.verify_share()` | Check share against commitments |
| Share aggregation | `keygen.aggregate_shares()` | Combine shares: sᵢ = ∑fⱼ(i) |
| Public key | `keygen.derive_public_key()` | Y = ∑(A₀ⱼ) |
| Group commitments | `keygen.derive_group_commitments()` | Aggregate coefficient commitments |
| Verification share | `keygen.derive_public_verification_share()` | Yᵢ from group commitments |
