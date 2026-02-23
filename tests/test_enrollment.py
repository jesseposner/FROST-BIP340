from frost import G, Participant, Q
from frost.lagrange import lagrange_coefficient


def test_enrollment(keygen_group):
    p1, p2, p3 = keygen_group

    p4 = Participant(index=4, threshold=2, participants=4)
    p1.participants = 4
    p2.participants = 4
    p3.participants = 4

    p1.generate_repair_shares((2,), 4)
    p2.generate_repair_shares((1,), 4)

    assert p1.verify_repair_share(p2.get_repair_share(p1.index), p2.repair_share_commitments, 4, 2)
    assert p2.verify_repair_share(p1.get_repair_share(p2.index), p1.repair_share_commitments, 4, 1)

    p1.aggregate_repair_shares((p2.get_repair_share(p1.index),))
    p2.aggregate_repair_shares((p1.get_repair_share(p2.index),))

    group_commitments = p1.group_commitments

    assert p4.verify_aggregate_repair_share(
        p1.aggregate_repair_share,
        (p1.repair_share_commitments, p2.repair_share_commitments),
        1,
        (1, 2),
        group_commitments,
    )
    assert p4.verify_aggregate_repair_share(
        p2.aggregate_repair_share,
        (p1.repair_share_commitments, p2.repair_share_commitments),
        2,
        (1, 2),
        group_commitments,
    )

    p4.repair_share((p1.aggregate_repair_share, p2.aggregate_repair_share))

    # Reconstruct secret from different subsets
    pk1 = p1.public_key

    l1 = int(lagrange_coefficient((2,), 1))
    l2 = int(lagrange_coefficient((1,), 2))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    l1 = int(lagrange_coefficient((4,), 1))
    l4 = int(lagrange_coefficient((1,), 4))
    secret = ((p1.aggregate_share * l1) + (p4.aggregate_share * l4)) % Q
    assert secret * G == pk1

    l2 = int(lagrange_coefficient((4,), 2))
    l4 = int(lagrange_coefficient((2,), 4))
    secret = ((p2.aggregate_share * l2) + (p4.aggregate_share * l4)) % Q
    assert secret * G == pk1

    l1 = int(lagrange_coefficient((2, 4), 1))
    l2 = int(lagrange_coefficient((1, 4), 2))
    l4 = int(lagrange_coefficient((1, 2), 4))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p4.aggregate_share * l4)
    ) % Q
    assert secret * G == pk1


def test_disenrollment(keygen_group):
    p1, p2, p3 = keygen_group

    p1.participants = 2
    p2.participants = 2

    p1.init_refresh()
    p2.init_refresh()

    p1.generate_shares()
    p2.generate_shares()

    p1.aggregate_shares((p2.shares[p1.index - 1],))
    p2.aggregate_shares((p1.shares[p2.index - 1],))

    assert p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
    assert p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)

    # Reconstruct secret
    pk1 = p1.public_key

    l1 = int(lagrange_coefficient((2,), 1))
    l2 = int(lagrange_coefficient((1,), 2))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    # p3's old share should no longer reconstruct the secret
    l1 = int(lagrange_coefficient((3,), 1))
    l3 = int(lagrange_coefficient((1,), 3))
    secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
    assert secret * G != pk1

    l2 = int(lagrange_coefficient((3,), 2))
    l3 = int(lagrange_coefficient((2,), 3))
    secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
    assert secret * G != pk1

    l1 = int(lagrange_coefficient((2, 3), 1))
    l2 = int(lagrange_coefficient((1, 3), 2))
    l3 = int(lagrange_coefficient((1, 2), 3))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)
    ) % Q
    assert secret * G != pk1
