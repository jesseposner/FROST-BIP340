"""
Share repair and enrollment for FROST threshold signatures.

When a participant loses their secret share (hardware failure, key loss), the
remaining participants can collaborate to reconstruct it without revealing the
group secret. This uses the same polynomial interpolation as DKG, applied to
existing shares.

The repair protocol:
1. Each helper generates random "repair shares" that encode their contribution
   (weighted by their Lagrange coefficient for the target index)
2. Helpers exchange and verify repair shares against commitments
3. An aggregator for each helper sums their received repair shares
4. The victim sums all aggregate repair shares to recover their original share

Enrollment (adding a new participant) uses the same mechanism: the repair
target is the new participant's index, and helpers contribute shares that
give the new member a valid share of the existing group secret.

References:
- Proactive Secret Sharing (Herzberg et al., 1995)
- FROST share repair follows similar principles
"""

from .keygen import derive_public_verification_share
from .lagrange import lagrange_coefficient
from .point import G, Point
from .scalar import Scalar


def generate_repair_shares(
    aggregate_share: Scalar,
    threshold: int,
    repair_participants: tuple[int, ...],
    target_index: int,
    own_index: int,
) -> tuple[tuple[Scalar, ...], tuple[Point, ...], tuple[int, ...]]:
    """Generate repair shares to help recover a lost participant's share.

    Each helper computes their Lagrange-weighted contribution to the target's
    share, then splits it into random additive shares (one per helper). The
    shares sum to λᵢ·sᵢ (where λᵢ is the helper's Lagrange coefficient for
    the target index and sᵢ is the helper's aggregate share).

    This additive splitting prevents any single helper from learning another
    helper's weighted contribution, preserving the secrecy of individual shares.

    Parameters:
        aggregate_share: This helper's aggregate share sᵢ.
        threshold: The group's signing threshold t.
        repair_participants: Indexes of all participants helping with the repair
            (not including own_index).
        target_index: The index of the participant whose share is being repaired.
        own_index: This helper's index.

    Returns:
        (shares, commitments, sorted_repair_participants) where:
        - shares: tuple of t Scalars, one per helper (including self)
        - commitments: tuple of t Points, the public commitments to each share
        - sorted_repair_participants: the full sorted set of helper indexes
    """
    sorted_participants = tuple(sorted((*repair_participants, own_index)))

    lam = lagrange_coefficient(sorted_participants, own_index, target_index)
    weighted_share = lam * aggregate_share

    # Split into t-1 random shares plus a final share that makes them sum correctly
    random_shares = tuple(Scalar.random() for _ in range(threshold - 1))
    random_sum = Scalar(0)
    for s in random_shares:
        random_sum = random_sum + s
    final_share = weighted_share - random_sum

    shares = (*random_shares, final_share)
    commitments = tuple(int(s) * G for s in shares)
    return (shares, commitments, sorted_participants)


def get_repair_share(
    repair_shares: tuple[Scalar, ...],
    repair_participants: tuple[int, ...],
    participant_index: int,
) -> Scalar:
    """Retrieve the repair share designated for a specific participant.

    Repair shares are distributed one per helper in the sorted participant order.
    This function looks up the share for a given participant by index.

    Parameters:
        repair_shares: All generated repair shares.
        repair_participants: Sorted indexes of all helpers.
        participant_index: The index of the helper requesting their share.

    Returns:
        The repair share for the requested participant.

    Raises:
        ValueError: If participant_index is not in the repair set.
    """
    if participant_index not in repair_participants:
        raise ValueError("Participant index is not in the repair set.")
    mapped_index = repair_participants.index(participant_index)
    return repair_shares[mapped_index]


def get_repair_share_commitment(
    repair_share_commitments: tuple[Point, ...],
    repair_participants: tuple[int, ...],
    participant_index: int,
) -> Point:
    """Retrieve the repair share commitment for a specific participant.

    Analogous to get_repair_share but for the public commitments. Used during
    verification to check that received shares match their published commitments.

    Parameters:
        repair_share_commitments: All commitments for the repair shares.
        repair_participants: Sorted indexes of all helpers.
        participant_index: The index of the helper whose commitment to look up.

    Returns:
        The commitment for the requested participant's repair share.

    Raises:
        ValueError: If participant_index is not in the repair set.
    """
    if participant_index not in repair_participants:
        raise ValueError("Participant index is not in the repair set.")
    mapped_index = repair_participants.index(participant_index)
    return repair_share_commitments[mapped_index]


def verify_repair_share(
    repair_share: Scalar,
    repair_share_commitments: tuple[Point, ...],
    own_index: int,
    repair_participants: tuple[int, ...],
    target_index: int,
    dealer_index: int,
    group_commitments: tuple[Point, ...],
) -> bool:
    """Verify a repair share against its commitment and group commitments.

    Two checks are performed:
    1. The share matches its commitment: share·G == commitment
    2. The dealer's commitments are consistent with the group polynomial:
       λ·dealer_public_share == ∑(commitments)

    The second check ensures the dealer actually used their real share (weighted
    by the correct Lagrange coefficient) to generate the repair shares.

    Parameters:
        repair_share: The share to verify.
        repair_share_commitments: All commitments from the dealer.
        own_index: This verifier's index.
        repair_participants: Sorted indexes of all helpers.
        target_index: Index of the participant being repaired.
        dealer_index: Index of the participant who generated these shares.
        group_commitments: The group coefficient commitments.

    Returns:
        True if both checks pass, False otherwise.
    """
    # Check 1: share matches its commitment
    expected_commitment = get_repair_share_commitment(
        repair_share_commitments, repair_participants, own_index
    )
    if int(repair_share) * G != expected_commitment:
        return False

    # Check 2: dealer's commitments are consistent with group polynomial
    lam = lagrange_coefficient(repair_participants, dealer_index, target_index)
    dealer_public_share = derive_public_verification_share(group_commitments, dealer_index)
    return int(lam) * dealer_public_share == sum(repair_share_commitments, Point())


def verify_aggregate_repair_share(
    aggregate_repair_share: Scalar,
    repair_share_commitments: tuple[tuple[Point, ...], ...],
    aggregator_index: int,
    target_index: int,
    threshold: int,
    repair_participants: tuple[int, ...],
    group_commitments: tuple[Point, ...],
) -> bool:
    """Verify an aggregate repair share against all dealers' commitments.

    This performs a comprehensive verification:
    1. For each dealer, check that their commitments are consistent with the
       group polynomial (same check as verify_repair_share, step 2)
    2. Check that the aggregate share matches the sum of all dealers'
       commitments for the aggregator's index

    Parameters:
        aggregate_repair_share: The aggregated repair share to verify.
        repair_share_commitments: Each dealer's commitment tuple, one per dealer.
        aggregator_index: Index of the participant who aggregated.
        target_index: Index of the participant being repaired.
        threshold: The group's signing threshold.
        repair_participants: Sorted indexes of all helpers.
        group_commitments: The group coefficient commitments.

    Returns:
        True if the aggregate repair share is valid, False otherwise.

    Raises:
        ValueError: If the number of commitment tuples doesn't match the threshold.
    """
    if len(repair_share_commitments) != threshold:
        raise ValueError("The number of repair share commitments must match the threshold.")

    # Check each dealer's commitments against the group polynomial
    for dealer_index, commitments in zip(
        repair_participants, repair_share_commitments, strict=True
    ):
        lam = lagrange_coefficient(repair_participants, dealer_index, target_index)
        dealer_public_share = derive_public_verification_share(group_commitments, dealer_index)
        if int(lam) * dealer_public_share != sum(commitments, Point()):
            return False

    # Check that aggregate share matches the sum of commitments for aggregator
    aggregate_commitment = sum(
        tuple(
            get_repair_share_commitment(commitments, repair_participants, aggregator_index)
            for commitments in repair_share_commitments
        ),
        Point(),
    )

    return int(aggregate_repair_share) * G == aggregate_commitment


def aggregate_repair_shares(
    own_repair_share: Scalar,
    other_shares: tuple[Scalar, ...],
) -> Scalar:
    """Aggregate repair shares from multiple helpers.

    Each helper receives one repair share from every other helper (and keeps
    one for themselves). Summing these gives the helper's "aggregate repair
    share", which encodes their contribution to the reconstruction.

    Parameters:
        own_repair_share: This helper's own repair share (from their own generation).
        other_shares: Repair shares received from other helpers.

    Returns:
        The aggregate repair share.
    """
    result = own_repair_share
    for share in other_shares:
        result = result + share
    return result


def reconstruct_share(
    aggregate_repair_shares: tuple[Scalar, ...],
) -> Scalar:
    """Reconstruct a lost share from aggregate repair shares.

    The repaired participant receives one aggregate repair share from each
    helper. Summing them recovers the original aggregate share, because each
    helper's weighted contribution (λᵢ·sᵢ) reconstructs the polynomial
    evaluation at the target index.

    Parameters:
        aggregate_repair_shares: One aggregate repair share per helper.

    Returns:
        The reconstructed aggregate share.
    """
    result = Scalar(0)
    for share in aggregate_repair_shares:
        result = result + share
    return result
