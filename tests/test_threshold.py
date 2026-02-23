import secrets

from frost import G, Participant, Q


def test_threshold_decrease():
    """Test threshold decrease with a 3-of-4 group decremented to 2-of-4."""
    p1 = Participant(index=1, threshold=3, participants=4)
    p2 = Participant(index=2, threshold=3, participants=4)
    p3 = Participant(index=3, threshold=3, participants=4)
    p4 = Participant(index=4, threshold=3, participants=4)

    # Round 1.1, 1.2, 1.3, and 1.4
    p1.init_keygen()
    p2.init_keygen()
    p3.init_keygen()
    p4.init_keygen()

    # Round 2.1
    p1.generate_shares()
    p2.generate_shares()
    p3.generate_shares()
    p4.generate_shares()

    # Round 2.3
    p1.aggregate_shares(
        (p2.shares[p1.index - 1], p3.shares[p1.index - 1], p4.shares[p1.index - 1])
    )
    p2.aggregate_shares(
        (p1.shares[p2.index - 1], p3.shares[p2.index - 1], p4.shares[p2.index - 1])
    )
    p3.aggregate_shares(
        (p1.shares[p3.index - 1], p2.shares[p3.index - 1], p4.shares[p3.index - 1])
    )
    p4.aggregate_shares(
        (p1.shares[p4.index - 1], p2.shares[p4.index - 1], p3.shares[p4.index - 1])
    )

    # Round 2.4
    p1.derive_public_key(
        (
            p2.coefficient_commitments[0],
            p3.coefficient_commitments[0],
            p4.coefficient_commitments[0],
        )
    )
    p2.derive_public_key(
        (
            p1.coefficient_commitments[0],
            p3.coefficient_commitments[0],
            p4.coefficient_commitments[0],
        )
    )
    p3.derive_public_key(
        (
            p1.coefficient_commitments[0],
            p2.coefficient_commitments[0],
            p4.coefficient_commitments[0],
        )
    )
    p4.derive_public_key(
        (
            p1.coefficient_commitments[0],
            p2.coefficient_commitments[0],
            p3.coefficient_commitments[0],
        )
    )

    pk1 = p1.public_key
    assert p1.public_key == p2.public_key
    assert p2.public_key == p3.public_key
    assert p3.public_key == p4.public_key

    p1.derive_group_commitments(
        (p2.coefficient_commitments, p3.coefficient_commitments, p4.coefficient_commitments)
    )
    p2.derive_group_commitments(
        (p1.coefficient_commitments, p3.coefficient_commitments, p4.coefficient_commitments)
    )
    p3.derive_group_commitments(
        (p1.coefficient_commitments, p2.coefficient_commitments, p4.coefficient_commitments)
    )
    p4.derive_group_commitments(
        (p1.coefficient_commitments, p2.coefficient_commitments, p3.coefficient_commitments)
    )

    assert p1.group_commitments == p2.group_commitments
    assert p2.group_commitments == p3.group_commitments
    assert p3.group_commitments == p4.group_commitments

    group_commitments = p1.group_commitments

    assert p1.verify_share(p1.aggregate_share, group_commitments, 3)
    assert p2.verify_share(p2.aggregate_share, group_commitments, 3)
    assert p3.verify_share(p3.aggregate_share, group_commitments, 3)
    assert p4.verify_share(p4.aggregate_share, group_commitments, 3)

    l1 = p1._lagrange_coefficient((2, 3))
    l2 = p2._lagrange_coefficient((1, 3))
    l3 = p3._lagrange_coefficient((1, 2))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)
    ) % Q
    assert secret * G == pk1

    # Compute and reveal share
    revealed_share_index = secrets.randbits(256) % Q
    revealed = Participant(index=revealed_share_index, threshold=3, participants=4)

    p1.generate_repair_shares((2, 3), revealed_share_index)
    p2.generate_repair_shares((1, 3), revealed_share_index)
    p3.generate_repair_shares((1, 2), revealed_share_index)

    assert p1.verify_repair_share(
        p2.get_repair_share(p1.index), p2.repair_share_commitments, revealed_share_index, 2
    )
    assert p1.verify_repair_share(
        p3.get_repair_share(p1.index), p3.repair_share_commitments, revealed_share_index, 3
    )
    assert p2.verify_repair_share(
        p1.get_repair_share(p2.index), p1.repair_share_commitments, revealed_share_index, 1
    )
    assert p2.verify_repair_share(
        p3.get_repair_share(p2.index), p3.repair_share_commitments, revealed_share_index, 3
    )
    assert p3.verify_repair_share(
        p1.get_repair_share(p3.index), p1.repair_share_commitments, revealed_share_index, 1
    )
    assert p3.verify_repair_share(
        p2.get_repair_share(p3.index), p2.repair_share_commitments, revealed_share_index, 2
    )

    p1.aggregate_repair_shares((p2.get_repair_share(p1.index), p3.get_repair_share(p1.index)))
    p2.aggregate_repair_shares((p1.get_repair_share(p2.index), p3.get_repair_share(p2.index)))
    p3.aggregate_repair_shares((p1.get_repair_share(p3.index), p2.get_repair_share(p3.index)))

    all_repair_commitments = (
        p1.repair_share_commitments,
        p2.repair_share_commitments,
        p3.repair_share_commitments,
    )

    assert revealed.verify_aggregate_repair_share(
        p1.aggregate_repair_share, all_repair_commitments, 1, (1, 2, 3), group_commitments
    )
    assert revealed.verify_aggregate_repair_share(
        p2.aggregate_repair_share, all_repair_commitments, 2, (1, 2, 3), group_commitments
    )
    assert revealed.verify_aggregate_repair_share(
        p3.aggregate_repair_share, all_repair_commitments, 3, (1, 2, 3), group_commitments
    )

    revealed.repair_share(
        (p1.aggregate_repair_share, p2.aggregate_repair_share, p3.aggregate_repair_share)
    )
    l1 = p1._lagrange_coefficient((2, revealed_share_index))
    l2 = p2._lagrange_coefficient((1, revealed_share_index))
    l4 = revealed._lagrange_coefficient((1, 2))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (revealed.aggregate_share * l4)
    ) % Q
    assert secret * G == pk1

    # Before decrement, 2-of-3 should NOT reconstruct
    l1 = p1._lagrange_coefficient((2,))
    l2 = p2._lagrange_coefficient((1,))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G != pk1

    # Decrement threshold
    p1.decrement_threshold(revealed.aggregate_share, revealed_share_index)
    p2.decrement_threshold(revealed.aggregate_share, revealed_share_index)
    p3.decrement_threshold(revealed.aggregate_share, revealed_share_index)
    p4.decrement_threshold(revealed.aggregate_share, revealed_share_index)

    # After decrement, 2-of-3 should reconstruct
    l1 = p1._lagrange_coefficient((2,))
    l2 = p2._lagrange_coefficient((1,))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    new_group_commitments1 = p1.group_commitments
    assert p1.group_commitments == p2.group_commitments
    assert p2.group_commitments == p3.group_commitments
    assert p3.group_commitments == p4.group_commitments
    assert group_commitments != new_group_commitments1

    new_group_commitments = new_group_commitments1

    assert p1.verify_share(p1.aggregate_share, new_group_commitments, 2)
    assert p2.verify_share(p2.aggregate_share, new_group_commitments, 2)
    assert p3.verify_share(p3.aggregate_share, new_group_commitments, 2)
    assert p4.verify_share(p4.aggregate_share, new_group_commitments, 2)


def test_threshold_increase(keygen_group):
    """Test threshold increase from 2-of-3 to 3-of-3."""
    p1, p2, p3 = keygen_group

    pk1 = p1.public_key

    # Before increase, 2-of-3 reconstructs
    l1 = p1._lagrange_coefficient((2,))
    l2 = p2._lagrange_coefficient((1,))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    p1.init_threshold_increase(3)
    p2.init_threshold_increase(3)
    p3.init_threshold_increase(3)

    p1.generate_shares()
    p2.generate_shares()
    p3.generate_shares()

    assert p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
    assert p1.verify_share(p3.shares[p1.index - 1], p3.coefficient_commitments, 2)

    assert p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)
    assert p2.verify_share(p3.shares[p2.index - 1], p3.coefficient_commitments, 2)

    assert p3.verify_share(p1.shares[p3.index - 1], p1.coefficient_commitments, 2)
    assert p3.verify_share(p2.shares[p3.index - 1], p2.coefficient_commitments, 2)

    p1.increase_threshold((p2.shares[p1.index - 1], p3.shares[p1.index - 1]))
    p2.increase_threshold((p1.shares[p2.index - 1], p3.shares[p2.index - 1]))
    p3.increase_threshold((p1.shares[p3.index - 1], p2.shares[p3.index - 1]))

    # After increase, 2-of-3 no longer reconstructs
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G != pk1

    # But 3-of-3 does
    l1 = p1._lagrange_coefficient((2, 3))
    l2 = p2._lagrange_coefficient((1, 3))
    l3 = p3._lagrange_coefficient((1, 2))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)
    ) % Q
    assert secret * G == pk1
