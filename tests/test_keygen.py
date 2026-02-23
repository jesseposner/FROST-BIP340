from frost import G, Q
from frost.lagrange import lagrange_coefficient


def test_keygen(keygen_group):
    p1, p2, p3 = keygen_group

    # Round 1.5: Verify proofs of knowledge
    assert p1.verify_proof_of_knowledge(
        p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2
    )
    assert p1.verify_proof_of_knowledge(
        p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3
    )

    assert p2.verify_proof_of_knowledge(
        p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1
    )
    assert p2.verify_proof_of_knowledge(
        p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3
    )

    assert p3.verify_proof_of_knowledge(
        p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1
    )
    assert p3.verify_proof_of_knowledge(
        p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2
    )

    # Round 2.2: Verify shares
    assert p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
    assert p1.verify_share(p3.shares[p1.index - 1], p3.coefficient_commitments, 2)

    assert p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)
    assert p2.verify_share(p3.shares[p2.index - 1], p3.coefficient_commitments, 2)

    assert p3.verify_share(p1.shares[p3.index - 1], p1.coefficient_commitments, 2)
    assert p3.verify_share(p2.shares[p3.index - 1], p2.coefficient_commitments, 2)

    # Reconstruct secret from different subsets
    pk1 = p1.public_key

    l1 = int(lagrange_coefficient((2,), 1))
    l2 = int(lagrange_coefficient((1,), 2))
    secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
    assert secret * G == pk1

    l1 = int(lagrange_coefficient((3,), 1))
    l3 = int(lagrange_coefficient((1,), 3))
    secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
    assert secret * G == pk1

    l2 = int(lagrange_coefficient((3,), 2))
    l3 = int(lagrange_coefficient((2,), 3))
    secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
    assert secret * G == pk1

    l1 = int(lagrange_coefficient((2, 3), 1))
    l2 = int(lagrange_coefficient((1, 3), 2))
    l3 = int(lagrange_coefficient((1, 2), 3))
    secret = (
        (p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)
    ) % Q
    assert secret * G == pk1
