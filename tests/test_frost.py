import unittest

from frost import FROST

class Tests(unittest.TestCase):
    def test_keygen(self):
        Q = FROST.secp256k1.Q
        G = FROST.secp256k1.G()

        p1 = FROST.Participant(index=1, threshold=2, participants=3)
        p2 = FROST.Participant(index=2, threshold=2, participants=3)
        p3 = FROST.Participant(index=3, threshold=2, participants=3)

        # Round 1.1, 1.2, 1.3, and 1.4
        p1.init_keygen()
        p2.init_keygen()
        p3.init_keygen()

        # Round 1.5
        self.assertTrue(
            p1.verify_proof_of_knowledge(p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2)
        )
        self.assertTrue(
            p1.verify_proof_of_knowledge(p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3)
        )

        self.assertTrue(
            p2.verify_proof_of_knowledge(p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1)
        )
        self.assertTrue(
            p2.verify_proof_of_knowledge(p3.proof_of_knowledge, p3.coefficient_commitments[0], index=3)
        )

        self.assertTrue(
            p3.verify_proof_of_knowledge(p1.proof_of_knowledge, p1.coefficient_commitments[0], index=1)
        )
        self.assertTrue(
            p3.verify_proof_of_knowledge(p2.proof_of_knowledge, p2.coefficient_commitments[0], index=2)
        )

        # Round 2.1
        p1.generate_shares()
        p2.generate_shares()
        p3.generate_shares()

        # Round 2.2
        self.assertTrue(
            p1.verify_share(p2.shares[p1.index-1], p2.coefficient_commitments)
        )
        self.assertTrue(
            p1.verify_share(p3.shares[p1.index-1], p3.coefficient_commitments)
        )

        self.assertTrue(
            p2.verify_share(p1.shares[p2.index-1], p1.coefficient_commitments)
        )
        self.assertTrue(
            p2.verify_share(p3.shares[p2.index-1], p3.coefficient_commitments)
        )

        self.assertTrue(
            p3.verify_share(p1.shares[p3.index-1], p1.coefficient_commitments)
        )
        self.assertTrue(
            p3.verify_share(p2.shares[p3.index-1], p2.coefficient_commitments)
        )

        # Round 2.3
        p1.aggregate_shares([p2.shares[p1.index-1], p3.shares[p1.index-1]])
        p2.aggregate_shares([p1.shares[p2.index-1], p3.shares[p2.index-1]])
        p3.aggregate_shares([p1.shares[p3.index-1], p2.shares[p3.index-1]])

        # Round 2.4
        pk1 = p1.derive_public_key([p2.coefficient_commitments[0], p3.coefficient_commitments[0]])
        pk2 = p2.derive_public_key([p1.coefficient_commitments[0], p3.coefficient_commitments[0]])
        pk3 = p3.derive_public_key([p1.coefficient_commitments[0], p2.coefficient_commitments[0]])

        self.assertEqual(pk1, pk2)
        self.assertEqual(pk2, pk3)

        # Reconstruct secret
        l1 = p1.lagrange_coefficient([2])
        l2 = p2.lagrange_coefficient([1])
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1.lagrange_coefficient([3])
        l3 = p3.lagrange_coefficient([1])
        secret = ((p1.aggregate_share * l1) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l2 = p2.lagrange_coefficient([3])
        l3 = p3.lagrange_coefficient([2])
        secret = ((p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

        l1 = p1.lagrange_coefficient([2, 3])
        l2 = p2.lagrange_coefficient([1, 3])
        l3 = p3.lagrange_coefficient([1, 2])
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2) + (p3.aggregate_share * l3)) % Q
        self.assertEqual(secret * G, pk1)

    def test_sign(self):
        p1 = FROST.Participant(index=1, threshold=2, participants=3)
        p2 = FROST.Participant(index=2, threshold=2, participants=3)
        p3 = FROST.Participant(index=3, threshold=2, participants=3)

        # KeyGen
        p1.init_keygen()
        p2.init_keygen()
        p3.init_keygen()

        p1.generate_shares()
        p2.generate_shares()
        p3.generate_shares()

        p1.aggregate_shares([p2.shares[p1.index-1], p3.shares[p1.index-1]])
        p2.aggregate_shares([p1.shares[p2.index-1], p3.shares[p2.index-1]])
        p3.aggregate_shares([p1.shares[p3.index-1], p2.shares[p3.index-1]])

        p1.derive_public_key([p2.coefficient_commitments[0], p3.coefficient_commitments[0]])
        p2.derive_public_key([p1.coefficient_commitments[0], p3.coefficient_commitments[0]])
        pk = p3.derive_public_key([p1.coefficient_commitments[0], p2.coefficient_commitments[0]])

        # NonceGen
        p1.generate_nonces(1)
        p2.generate_nonces(1)
        p3.generate_nonces(1)

        # Sign
        msg = b'fnord!'
        participant_indexes = [1, 2]
        agg = FROST.Aggregator(pk, msg, [p1.nonce_commitment_pairs, p2.nonce_commitment_pairs], participant_indexes)
        message, nonce_commitment_pairs = agg.signing_inputs()

        s1 = p1.sign(message, nonce_commitment_pairs, participant_indexes)
        s2 = p2.sign(message, nonce_commitment_pairs, participant_indexes)

        # σ = (R, z)
        sig = agg.signature([s1, s2])
        sig_bytes = bytes.fromhex(sig)
        nonce_commitment = FROST.Point.xonly_deserialize(sig_bytes[0:32].hex())
        z = int.from_bytes(sig_bytes[32:64], 'big')

        # verify
        G = FROST.secp256k1.G()
        # c = H_2(R, Y, m)
        challenge_hash = FROST.Aggregator.challenge_hash(nonce_commitment, pk, msg)
        # Negate Y if Y.y is odd
        if pk.y % 2 != 0:
            pk = -pk

        # R ≟ g^z * Y^-c
        self.assertTrue(nonce_commitment == (z * G) + (FROST.secp256k1.Q - challenge_hash) * pk)