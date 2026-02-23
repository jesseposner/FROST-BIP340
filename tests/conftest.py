import pytest

from frost import Participant


@pytest.fixture
def keygen_group():
    """A 2-of-3 FROST group that has completed DKG."""
    p1 = Participant(index=1, threshold=2, participants=3)
    p2 = Participant(index=2, threshold=2, participants=3)
    p3 = Participant(index=3, threshold=2, participants=3)

    p1.init_keygen()
    p2.init_keygen()
    p3.init_keygen()

    p1.generate_shares()
    p2.generate_shares()
    p3.generate_shares()

    p1.aggregate_shares((p2.shares[p1.index - 1], p3.shares[p1.index - 1]))
    p2.aggregate_shares((p1.shares[p2.index - 1], p3.shares[p2.index - 1]))
    p3.aggregate_shares((p1.shares[p3.index - 1], p2.shares[p3.index - 1]))

    p1.derive_public_key((p2.coefficient_commitments[0], p3.coefficient_commitments[0]))
    p2.derive_public_key((p1.coefficient_commitments[0], p3.coefficient_commitments[0]))
    p3.derive_public_key((p1.coefficient_commitments[0], p2.coefficient_commitments[0]))

    assert p1.public_key == p2.public_key
    assert p2.public_key == p3.public_key

    p1.derive_group_commitments((p2.coefficient_commitments, p3.coefficient_commitments))
    p2.derive_group_commitments((p1.coefficient_commitments, p3.coefficient_commitments))
    p3.derive_group_commitments((p1.coefficient_commitments, p2.coefficient_commitments))

    assert p1.group_commitments == p2.group_commitments
    assert p2.group_commitments == p3.group_commitments

    assert p1.verify_share(p1.aggregate_share, p1.group_commitments, 2)
    assert p2.verify_share(p2.aggregate_share, p1.group_commitments, 2)
    assert p3.verify_share(p3.aggregate_share, p1.group_commitments, 2)

    return p1, p2, p3
