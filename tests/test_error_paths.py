"""Error path tests for parameter validation and edge cases.

These tests verify that the code raises appropriate exceptions for
invalid inputs, missing state, and boundary conditions.
"""

import pytest

from frost import Participant, Point
from frost.repair import get_repair_share, get_repair_share_commitment
from frost.scalar import Scalar


def test_threshold_below_minimum():
    """Threshold must be at least 2."""
    with pytest.raises(ValueError, match="at least 2"):
        Participant(index=1, threshold=1, participants=3)


def test_participants_below_threshold():
    """Number of participants must be at least the threshold."""
    with pytest.raises(ValueError, match="at least the threshold"):
        Participant(index=1, threshold=3, participants=2)


def test_index_below_minimum():
    """Participant index must be at least 1."""
    with pytest.raises(ValueError, match="at least 1"):
        Participant(index=0, threshold=2, participants=3)


def test_non_integer_arguments():
    """All constructor arguments must be integers."""
    with pytest.raises(ValueError, match="must be integers"):
        Participant(index="1", threshold=2, participants=3)


def test_sign_without_nonce():
    """Signing without generating a nonce pair raises ValueError."""
    p = Participant(index=1, threshold=2, participants=3)
    p.init_keygen()
    with pytest.raises(ValueError, match="Nonce pair"):
        p.sign(b"msg", ((Point(), Point()),) * 3, (1, 2))


def test_public_verification_share_without_aggregate():
    """Accessing verification share without aggregate raises ValueError."""
    p = Participant(index=1, threshold=2, participants=3)
    with pytest.raises(ValueError, match="Aggregate share"):
        p.public_verification_share()


def test_aggregate_repair_shares_without_init():
    """Aggregating repair shares without generating them raises ValueError."""
    p = Participant(index=1, threshold=2, participants=3)
    with pytest.raises(ValueError, match="Repair shares"):
        p.aggregate_repair_shares((1, 2))


def test_repair_share_when_not_lost():
    """Repairing a share that hasn't been lost raises ValueError."""
    p = Participant(index=1, threshold=2, participants=3)
    p.aggregate_share = 42
    with pytest.raises(ValueError, match="has not been lost"):
        p.repair_share((1, 2))


def test_get_repair_share_invalid_index():
    """get_repair_share raises ValueError for unknown participant index."""
    shares = (Scalar(1), Scalar(2))
    participants = (1, 2)
    with pytest.raises(ValueError, match="not in the repair set"):
        get_repair_share(shares, participants, 99)


def test_get_repair_share_commitment_invalid_index():
    """get_repair_share_commitment raises ValueError for unknown participant."""
    commitments = (Point(), Point())
    participants = (1, 2)
    with pytest.raises(ValueError, match="not in the repair set"):
        get_repair_share_commitment(commitments, participants, 99)


def test_decrement_threshold_own_share():
    """Cannot decrement threshold using own revealed share."""
    participants = [Participant(index=i, threshold=2, participants=3) for i in range(1, 4)]
    for p in participants:
        p.init_keygen()
    for p in participants:
        p.generate_shares()
    for receiver in participants:
        other_shares = tuple(
            sender.shares[receiver.index - 1]
            for sender in participants
            if sender.index != receiver.index
        )
        receiver.aggregate_shares(other_shares)
    for p in participants:
        other_commitments = tuple(
            other.coefficient_commitments[0]
            for other in participants
            if other.index != p.index
        )
        p.derive_public_key(other_commitments)
    for p in participants:
        other_ccs = tuple(
            other.coefficient_commitments
            for other in participants
            if other.index != p.index
        )
        p.derive_group_commitments(other_ccs)

    p1 = participants[0]
    with pytest.raises(ValueError, match="Cannot decrement using own share"):
        p1.decrement_threshold(p1.aggregate_share, p1.index)


def test_lift_x_invalid():
    """lift_x with x >= P raises ValueError."""
    from frost.constants import P as FIELD_P

    with pytest.raises(ValueError):
        Point.lift_x(FIELD_P)


def test_lift_x_no_solution():
    """lift_x with x that has no square root raises ValueError."""
    with pytest.raises(ValueError):
        Point.lift_x(0)
