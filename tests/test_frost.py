import unittest

from frost import Point, Participant, Aggregator, Q, G


class Tests(unittest.TestCase):

    def setUp(self):
        self.p1 = Participant(index=1, threshold=2, participants=3)
        self.p2 = Participant(index=2, threshold=2, participants=3)
        self.p3 = Participant(index=3, threshold=2, participants=3)

        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        # Round 1.1, 1.2, 1.3, and 1.4
        p1.init_keygen()
        p2.init_keygen()
        p3.init_keygen()

        # Round 2.1
        p1.generate_shares()
        p2.generate_shares()
        p3.generate_shares()

        # Round 2.3
        p1.aggregate_shares((p2.shares[p1.index - 1], p3.shares[p1.index - 1]))
        p2.aggregate_shares((p1.shares[p2.index - 1], p3.shares[p2.index - 1]))
        p3.aggregate_shares((p1.shares[p3.index - 1], p2.shares[p3.index - 1]))

        # Round 2.4
        p1.derive_public_key(
            (p2.coefficient_commitments[0], p3.coefficient_commitments[0])
        )
        p2.derive_public_key(
            (p1.coefficient_commitments[0], p3.coefficient_commitments[0])
        )
        p3.derive_public_key(
            (p1.coefficient_commitments[0], p2.coefficient_commitments[0])
        )

        pk1 = p1.public_key
        pk2 = p2.public_key
        pk3 = p3.public_key

        self.assertEqual(pk1, pk2)
        self.assertEqual(pk2, pk3)

    def test_keygen(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        # Round 1.5
        self.assertTrue(
            p1.verify_proof_of_knowledge(
                p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2
            )
        )
        self.assertTrue(
            p1.verify_proof_of_knowledge(
                p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3
            )
        )

        self.assertTrue(
            p2.verify_proof_of_knowledge(
                p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1
            )
        )
        self.assertTrue(
            p2.verify_proof_of_knowledge(
                p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3
            )
        )

        self.assertTrue(
            p3.verify_proof_of_knowledge(
                p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1
            )
        )
        self.assertTrue(
            p3.verify_proof_of_knowledge(
                p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2
            )
        )

        # Round 2.2
        self.assertTrue(
            p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
        )
        self.assertTrue(
            p1.verify_share(p3.shares[p1.index - 1], p3.coefficient_commitments, 2)
        )

        self.assertTrue(
            p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)
        )
        self.assertTrue(
            p2.verify_share(p3.shares[p2.index - 1], p3.coefficient_commitments, 2)
        )

        self.assertTrue(
            p3.verify_share(p1.shares[p3.index - 1], p1.coefficient_commitments, 2)
        )
        self.assertTrue(
            p3.verify_share(p2.shares[p3.index - 1], p2.coefficient_commitments, 2)
        )

        # Reconstruct secret
        pk1 = p1.public_key

        l1 = p1._lagrange_coefficient((2,))
        l2 = p2._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((3,))
        l3 = p3._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l2 = p2._lagrange_coefficient((3,))
        l3 = p3._lagrange_coefficient((2,))
        secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((2, 3))
        l2 = p2._lagrange_coefficient((1, 3))
        l3 = p3._lagrange_coefficient((1, 2))
        secret = (
            (p1.aggregate_share * l1)
            + (p2.aggregate_share * l2)
            + (p3.aggregate_share * l3)
        ) % Q
        self.assertEqual(secret * G, pk1)

    def test_sign(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        pk = p1.public_key

        # NonceGen
        p1.generate_nonce_pair()
        p2.generate_nonce_pair()
        p3.generate_nonce_pair()

        # Sign
        msg = b"fnord!"
        participant_indexes = (1, 2)
        agg = Aggregator(
            pk,
            msg,
            (p1.nonce_commitment_pair, p2.nonce_commitment_pair),
            participant_indexes,
        )
        message, nonce_commitment_pairs = agg.signing_inputs()

        s1 = p1.sign(message, nonce_commitment_pairs, participant_indexes)
        s2 = p2.sign(message, nonce_commitment_pairs, participant_indexes)

        # σ = (R, z)
        sig = agg.signature((s1, s2))
        sig_bytes = bytes.fromhex(sig)
        nonce_commitment = Point.xonly_deserialize(sig_bytes[0:32].hex())
        z = int.from_bytes(sig_bytes[32:64], "big")

        # verify
        # c = H_2(R, Y, m)
        challenge_hash = Aggregator.challenge_hash(nonce_commitment, pk, msg)
        # Negate Y if Y.y is odd
        if pk.y % 2 != 0:
            pk = -pk

        # R ≟ g^z * Y^-c
        self.assertTrue(nonce_commitment == (z * G) + (Q - challenge_hash) * pk)

    def test_refresh(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        p1.init_refresh()
        p2.init_refresh()
        p3.init_refresh()

        p1.generate_shares()
        p2.generate_shares()
        p3.generate_shares()

        p1.aggregate_shares((p2.shares[p1.index - 1], p3.shares[p1.index - 1]))
        p2.aggregate_shares((p1.shares[p2.index - 1], p3.shares[p2.index - 1]))
        p3.aggregate_shares((p1.shares[p3.index - 1], p2.shares[p3.index - 1]))

        self.assertTrue(
            p1.verify_share(p2.shares[p1.index - 1], p2.coefficient_commitments, 2)
        )
        self.assertTrue(
            p1.verify_share(p3.shares[p1.index - 1], p3.coefficient_commitments, 2)
        )

        self.assertTrue(
            p2.verify_share(p1.shares[p2.index - 1], p1.coefficient_commitments, 2)
        )
        self.assertTrue(
            p2.verify_share(p3.shares[p2.index - 1], p3.coefficient_commitments, 2)
        )

        self.assertTrue(
            p3.verify_share(p1.shares[p3.index - 1], p1.coefficient_commitments, 2)
        )
        self.assertTrue(
            p3.verify_share(p2.shares[p3.index - 1], p2.coefficient_commitments, 2)
        )

        # Reconstruct secret
        pk1 = p1.public_key

        l1 = p1._lagrange_coefficient((2,))
        l2 = p2._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((3,))
        l3 = p3._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l2 = p2._lagrange_coefficient((3,))
        l3 = p3._lagrange_coefficient((2,))
        secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((2, 3))
        l2 = p2._lagrange_coefficient((1, 3))
        l3 = p3._lagrange_coefficient((1, 2))
        secret = (
            (p1.aggregate_share * l1)
            + (p2.aggregate_share * l2)
            + (p3.aggregate_share * l3)
        ) % Q
        self.assertEqual(secret * G, pk1)

    def test_repair(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        # repair share for p1
        lost_share = p1.aggregate_share
        p1.aggregate_share = None
        p2.generate_repair_shares((3,), 1)
        p3.generate_repair_shares((2,), 1)

        p2.aggregate_repair_shares((p3.repair_shares[1],))
        p3.aggregate_repair_shares((p2.repair_shares[1],))

        p1.repair_share((p2.aggregate_repair_share, p3.aggregate_repair_share))
        self.assertEqual(lost_share, p1.aggregate_share)

        # repair share for p2
        lost_share = p2.aggregate_share
        p2.aggregate_share = None
        p1.generate_repair_shares((3,), 2)
        p3.generate_repair_shares((1,), 2)

        p1.aggregate_repair_shares((p3.repair_shares[1],))
        p3.aggregate_repair_shares((p1.repair_shares[1],))

        p2.repair_share((p1.aggregate_repair_share, p3.aggregate_repair_share))
        self.assertEqual(lost_share, p2.aggregate_share)

        # repair share for p3
        lost_share = p3.aggregate_share
        p3.aggregate_share = None
        p1.generate_repair_shares((2,), 3)
        p2.generate_repair_shares((1,), 3)

        p1.aggregate_repair_shares((p2.repair_shares[1],))
        p2.aggregate_repair_shares((p1.repair_shares[1],))

        p3.repair_share((p1.aggregate_repair_share, p2.aggregate_repair_share))
        self.assertEqual(lost_share, p3.aggregate_share)

    def test_enrollment(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        p4 = Participant(index=4, threshold=2, participants=4)
        p1.participants = 4
        p2.participants = 4
        p3.participants = 4

        p1.generate_repair_shares((2,), 4)
        p2.generate_repair_shares((1,), 4)

        p1.aggregate_repair_shares((p2.repair_shares[1],))
        p2.aggregate_repair_shares((p1.repair_shares[1],))

        p4.repair_share((p1.aggregate_repair_share, p2.aggregate_repair_share))

        # Reconstruct secret
        pk1 = p1.public_key

        l1 = p1._lagrange_coefficient((2,))
        l2 = p2._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((4,))
        l4 = p4._lagrange_coefficient((1,))
        secret = ((p1.aggregate_share * l1) + (p4.aggregate_share * l4)) % Q
        self.assertEqual(secret * G, pk1)

        l2 = p2._lagrange_coefficient((4,))
        l4 = p4._lagrange_coefficient((2,))
        secret = ((p2.aggregate_share * l2) + (p4.aggregate_share * l4)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1._lagrange_coefficient((2, 4))
        l2 = p2._lagrange_coefficient((1, 4))
        l4 = p4._lagrange_coefficient((1, 2))
        secret = (
            (p1.aggregate_share * l1)
            + (p2.aggregate_share * l2)
            + (p4.aggregate_share * l4)
        ) % Q
        self.assertEqual(secret * G, pk1)
