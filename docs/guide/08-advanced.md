# Advanced Operations

This chapter covers operations beyond basic DKG and signing: share repair,
share refresh, threshold changes, and coefficient commitment derivation. These
are independent features that address real-world operational needs: recovering
from key loss, rotating shares, adjusting security parameters, and maintaining
consistent group state after changes.

## Share Repair

The repair protocol follows the Repairable Threshold Scheme construction
from Laing and Stinson ("A Survey and Refinement of Repairable Threshold
Schemes," 2018), based on additive splitting of Lagrange-weighted
contributions.

When a participant loses their aggregate share (hardware failure, corrupted
backup), the remaining participants can reconstruct it without revealing the
group secret. The requirement: at least t participants (the threshold) must
collaborate as helpers.

### Why Not Just Interpolate?

Lagrange interpolation (Chapter 4) could reconstruct the lost share, but it
would require the helpers to pool their shares in one place, which would
momentarily reconstruct the group secret. The repair protocol avoids this by
using *additive splitting*: each helper's contribution is broken into random
pieces that are distributed among the helpers, so no single helper learns
another's weighted contribution.

### The Repair Protocol

Suppose Carol (index 3) loses her share in a 2-of-3 group. Alice (index 1) and
Bob (index 2) are the helpers.

**Step 1: Generate repair shares.** Each helper computes their Lagrange-weighted
contribution to Carol's share: λᵢ·sᵢ (where λᵢ is evaluated at Carol's
index 3). Then they split this value into random additive shares, one per
helper.

Alice splits λ₁·s₁ into two random values (r_AA, r_AB) such that
r_AA + r_AB = λ₁·s₁. She keeps r_AA and sends r_AB to Bob. Bob does the same
with his contribution λ₂·s₂.

```python
from frost.repair import generate_repair_shares

shares, commitments, sorted_participants = generate_repair_shares(
    aggregate_share, threshold=2,
    repair_participants=(2,), target_index=3, own_index=1,
)
```

**Step 2: Verify repair shares.** Each helper verifies the shares they receive
from other helpers against published commitments, catching any cheating before
proceeding.

```python
from frost.repair import verify_repair_share

assert verify_repair_share(
    repair_share, commitments, own_index,
    repair_participants, target_index,
    dealer_index, group_commitments,
)
```

**Step 3: Aggregate.** Each helper sums the repair shares they hold (their own
plus those received from others) to produce an aggregate repair share.

```python
from frost.repair import aggregate_repair_shares

agg = aggregate_repair_shares(own_repair_share, other_shares)
```

**Step 4: Reconstruct.** Carol receives one aggregate repair share from each
helper and sums them to recover her original aggregate share.

```python
from frost.repair import reconstruct_share

recovered = reconstruct_share(aggregate_repair_shares_tuple)
```

The result equals Carol's original s₃, because the helpers' Lagrange-weighted
contributions sum to exactly f(3) by the interpolation property:

    ∑(λᵢ·sᵢ) evaluated at index 3 = F(3) = s₃

### Enrollment

Enrollment, adding a new participant, is share repair where the target index
is a new participant who never had a share. The same protocol gives the
newcomer a valid share of the existing group secret. No new DKG is needed, and
the group public key doesn't change.

### Disenrollment

Disenrollment, removing a participant, uses share refresh (see below). The
remaining participants run a refresh among themselves, excluding the
departing participant entirely. The removed participant's old share no longer
combines with the refreshed shares to reconstruct the secret. The group
public key is preserved.

## Share Refresh

Share refresh (Herzberg et al., "Proactive Secret Sharing Or: How to Cope
With Perpetual Leakage," CRYPTO '95) allows participants to periodically
randomize their shares without changing the group secret. Each participant
generates a zero-constant-term polynomial and distributes evaluations to
all other participants. Adding these evaluations to existing shares produces
new shares on a different polynomial with the same constant term (the group
secret). Any shares from the previous epoch become useless.

```python
from frost.polynomial import generate_refresh_polynomial, evaluate_polynomial

refresh_poly = generate_refresh_polynomial(threshold)
# refresh_poly[0] == 0: the constant term is zero, preserving the secret
```

This is used for periodic key rotation (limiting the window an adversary has
to collect shares), disenrollment (refreshing among a subset excludes the
departing participant), and post-compromise recovery.

**Security caveat: the adjacent assumption.** Herzberg's refresh scheme
assumes that if an adversary corrupts a party during a refresh phase, they
are corrupted in *both* adjacent time periods. Xia et al. ("Provably Secure
Proactive Secret Sharing Without the Adjacent Assumption," ProvSec 2019)
show that without this assumption, a mobile adversary who compromises
different parties across refresh boundaries can combine old and new share
information to recover the secret. In practice, this means refresh-phase
traffic must be protected with the same rigor as the shares themselves:
an adversary who observes both a pre-refresh share and the refresh
protocol messages can potentially bridge epochs.

## Threshold Changes

Threshold modification techniques are based on Desmedt and Jajodia
("Redistributing Secret Shares to New Access Structures," 1997) and
formalized by Nojoumian and Stinson ("On Dealer-Free Dynamic Threshold
Schemes," 2013), who term the increase method "zero addition" and the
decrease method "public evaluation."

Sometimes the security requirements of a group change. A 2-of-3 group might
need to become 3-of-3 (stricter security) or 2-of-2 (a participant is leaving).

### Threshold Increase

To raise the threshold from t to t', participants jointly generate new
polynomials of degree (t' - 2) and distribute evaluations, just like a
mini-DKG. Each participant adjusts their aggregate share by incorporating the
new evaluations:

```python
from frost.threshold import increase_threshold

new_share = increase_threshold(
    aggregate_share, own_new_shares, other_new_shares, index,
)
```

The group secret remains unchanged. Only the degree of the underlying polynomial
increases, which raises the number of shares required for reconstruction. The
mechanism is analogous to adding higher-degree terms to the polynomial while
keeping the constant term (the secret) fixed.

### Threshold Decrease

Decreasing the threshold is fundamentally different: it requires a participant
to publicly reveal their share. This is destructive, the revealing participant
permanently loses their share and can no longer participate.

Given the revealed share f(j), each remaining participant computes their new
share on a lower-degree polynomial:

    f'(i) = f(j) - j·(f(i) - f(j)) / (i - j)

This is polynomial division: "factoring out" the revealed participant's
contribution. The result is a degree-(t-2) polynomial with the same constant
term (the group secret is preserved).

```python
from frost.threshold import decrement_threshold

new_share, new_group_commitments = decrement_threshold(
    aggregate_share, revealed_share,
    revealed_index, own_index,
    group_commitments, threshold,
)
```

The function returns both the new share and updated group commitments, since
the old commitments correspond to the higher-degree polynomial and are no
longer valid.

## Coefficient Commitment Derivation

After threshold changes, the original group commitments are invalid because
they correspond to the old polynomial degree. The group needs new commitments
that match the updated polynomial.

Given public verification shares Yᵢ = sᵢ·G and their indexes, the new
coefficient commitments can be recovered via Vandermonde matrix inversion.

The Vandermonde matrix V has entries V[i][k] = indexᵢ^k. The coefficient
commitments C satisfy V·C = Y (where Y is the column of verification shares),
so:

    C = V⁻¹·Y

This is linear algebra over elliptic curve points: the matrix inversion is
performed in the scalar field, and the result is multiplied against points.

```python
from frost.threshold import derive_coefficient_commitments

new_commitments = derive_coefficient_commitments(
    public_verification_shares, participant_indexes,
)
```

The `matrix` module provides the Vandermonde construction and inversion:

```python
from frost.matrix import Matrix

V = Matrix.create_vandermonde(indexes)
V_inv = V.inverse_matrix()
```

This derivation is used internally by `decrement_threshold` to produce the
updated group commitments, but it's also available directly for any situation
where coefficient commitments need to be recovered from verification shares.

## Summary

| Concept | Code reference | Purpose |
|---------|---------------|---------|
| Repair share generation | `repair.generate_repair_shares()` | Split λᵢ·sᵢ into additive shares |
| Repair share verification | `repair.verify_repair_share()` | Verify against commitments |
| Share reconstruction | `repair.reconstruct_share()` | Recover lost share from helpers |
| Threshold increase | `threshold.increase_threshold()` | Raise t by adding polynomial degree |
| Threshold decrease | `threshold.decrement_threshold()` | Lower t by revealing a share |
| Commitment derivation | `threshold.derive_coefficient_commitments()` | Recover commitments via Vandermonde |
