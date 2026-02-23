from frost import G, Q


def test_refresh(keygen_group):
    p1, p2, p3 = keygen_group

    p1.init_refresh()
    p2.init_refresh()
    p3.init_refresh()

    p1.generate_shares()
    p2.generate_shares()
    p3.generate_shares()

    p1.aggregate_shares((p2.shares[p1.index - 1], p3.shares[p1.index - 1]))
    p2.aggregate_shares((p1.shares[p2.index - 1], p3.shares[p2.index - 1]))
    p3.aggregate_shares((p1.shares[p3.index - 1], p2.shares[p3.index - 1]))

    assert p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
    assert p1.verify_share(p3.shares[p1.index - 1], p3.coefficient_commitments, 2)

    assert p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)
    assert p2.verify_share(p3.shares[p2.index - 1], p3.coefficient_commitments, 2)

    assert p3.verify_share(p1.shares[p3.index - 1], p1.coefficient_commitments, 2)
    assert p3.verify_share(p2.shares[p3.index - 1], p2.coefficient_commitments, 2)

    p1.derive_group_commitments((p2.coefficient_commitments, p3.coefficient_commitments))
    p2.derive_group_commitments((p1.coefficient_commitments, p3.coefficient_commitments))
    p3.derive_group_commitments((p1.coefficient_commitments, p2.coefficient_commitments))

    assert p1.group_commitments == p2.group_commitments
    assert p2.group_commitments == p3.group_commitments

    group_commitments = p1.group_commitments

    assert p1.verify_share(p1.aggregate_share, group_commitments, 2)
    assert p2.verify_share(p2.aggregate_share, group_commitments, 2)
    assert p3.verify_share(p3.aggregate_share, group_commitments, 2)

    # Reconstruct secret from different subsets
    pk1 = p1.public_key

    l1 = p1._lagrange_coefficient((2,))
    l2 = p2._lagrange_coefficient((1,))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    l1 = p1._lagrange_coefficient((3,))
    l3 = p3._lagrange_coefficient((1,))
    secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
    assert secret * G == pk1

    l2 = p2._lagrange_coefficient((3,))
    l3 = p3._lagrange_coefficient((2,))
    secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
    assert secret * G == pk1

    l1 = p1._lagrange_coefficient((2, 3))
    l2 = p2._lagrange_coefficient((1, 3))
    l3 = p3._lagrange_coefficient((1, 2))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)
    ) % Q
    assert secret * G == pk1
