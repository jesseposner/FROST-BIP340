def test_repair(keygen_group):
    p1, p2, p3 = keygen_group

    # repair share for p1
    lost_share = p1.aggregate_share
    p1.aggregate_share = None
    p2.generate_repair_shares((3,), 1)
    p3.generate_repair_shares((2,), 1)

    assert p2.verify_repair_share(p3.get_repair_share(p2.index), p3.repair_share_commitments, 1, 3)
    assert p3.verify_repair_share(p2.get_repair_share(p3.index), p2.repair_share_commitments, 1, 2)

    p2.aggregate_repair_shares((p3.get_repair_share(p2.index),))
    p3.aggregate_repair_shares((p2.get_repair_share(p3.index),))

    group_commitments = p1.group_commitments

    assert p1.verify_aggregate_repair_share(
        p2.aggregate_repair_share,
        (p2.repair_share_commitments, p3.repair_share_commitments),
        2,
        (2, 3),
        group_commitments,
    )
    assert p1.verify_aggregate_repair_share(
        p3.aggregate_repair_share,
        (p2.repair_share_commitments, p3.repair_share_commitments),
        3,
        (2, 3),
        group_commitments,
    )

    p1.repair_share((p2.aggregate_repair_share, p3.aggregate_repair_share))
    assert lost_share == p1.aggregate_share

    # repair share for p2
    lost_share = p2.aggregate_share
    p2.aggregate_share = None
    p1.generate_repair_shares((3,), 2)
    p3.generate_repair_shares((1,), 2)

    assert p1.verify_repair_share(p3.get_repair_share(p1.index), p3.repair_share_commitments, 2, 3)
    assert p3.verify_repair_share(p1.get_repair_share(p3.index), p1.repair_share_commitments, 2, 1)

    p1.aggregate_repair_shares((p3.get_repair_share(p1.index),))
    p3.aggregate_repair_shares((p1.get_repair_share(p3.index),))

    assert p2.verify_aggregate_repair_share(
        p1.aggregate_repair_share,
        (p1.repair_share_commitments, p3.repair_share_commitments),
        1,
        (1, 3),
        group_commitments,
    )
    assert p2.verify_aggregate_repair_share(
        p3.aggregate_repair_share,
        (p1.repair_share_commitments, p3.repair_share_commitments),
        3,
        (1, 3),
        group_commitments,
    )

    p2.repair_share((p1.aggregate_repair_share, p3.aggregate_repair_share))
    assert lost_share == p2.aggregate_share

    # repair share for p3
    lost_share = p3.aggregate_share
    p3.aggregate_share = None
    p1.generate_repair_shares((2,), 3)
    p2.generate_repair_shares((1,), 3)

    assert p1.verify_repair_share(p2.get_repair_share(p1.index), p2.repair_share_commitments, 3, 2)
    assert p2.verify_repair_share(p1.get_repair_share(p2.index), p1.repair_share_commitments, 3, 1)

    p1.aggregate_repair_shares((p2.get_repair_share(p1.index),))
    p2.aggregate_repair_shares((p1.get_repair_share(p2.index),))

    assert p3.verify_aggregate_repair_share(
        p1.aggregate_repair_share,
        (p1.repair_share_commitments, p2.repair_share_commitments),
        1,
        (1, 2),
        group_commitments,
    )
    assert p3.verify_aggregate_repair_share(
        p2.aggregate_repair_share,
        (p1.repair_share_commitments, p2.repair_share_commitments),
        2,
        (1, 2),
        group_commitments,
    )

    p3.repair_share((p1.aggregate_repair_share, p2.aggregate_repair_share))
    assert lost_share == p3.aggregate_share
