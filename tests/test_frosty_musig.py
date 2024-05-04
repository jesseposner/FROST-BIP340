import unittest

import secrets
from frost import Point, MusigParticipant, Participant, Aggregator, Q, G


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

    def test_sign(self):
        p1 = self.p1
        p2 = self.p2
        p3 = self.p3

        # Round 1

        Ri1_hashed = p1.sample_random_rij()
        Ri2_hashed = p2.sample_random_rij()

        all_commitments = (Ri1_hashed, Ri2_hashed)
        p1.nonce_R_ij_commitments = all_commitments
        p2.nonce_R_ij_commitments = all_commitments

        # Round 2. Send nonce Rij to all parties
        all_nonces = (
            p1.nonce_pair_r_ij[1],
            p2.nonce_pair_r_ij[1],
        )
        p1.nonce_R_ij = all_nonces
        p2.nonce_R_ij = all_nonces

        p1.validate_other_party_nonce_commitments()
        p2.validate_other_party_nonce_commitments()

        # Round 3.1
        p1.compute_aggregate_nonce_R_i()
        R_i = p2.compute_aggregate_nonce_R_i()

        m2 = MusigParticipant(index=2, participants=2)
        m2.generate_private_key()
        m2.generate_public_key()

        m2.generate_aggregate_public_key((p1.public_key,))

        m2.generate_nonce()
        m2.generate_aggregate_nonce_commitment((R_i,))

        # # Obtain other parties aggregate nonce commitments
        p1.final_aggregate_R = m2.aggregate_nonce_commitment
        p2.final_aggregate_R = m2.aggregate_nonce_commitment

        # # Round 3.2

        # # Sign
        msg = b"fnord!"
        psig2 = m2.partial_sign(msg)

        participant_indexes = (1, 2)
        pk = p1.public_key
        keyagg_coeff = m2.generate_keyagg_coeff(pk, [m2.public_key, pk])
        psig_1_1 = p1.partial_sign(msg, participant_indexes, p1.final_aggregate_R, m2.aggregate_public_key, keyagg_coeff)
        psig_2_1 = p2.partial_sign(msg, participant_indexes, p2.final_aggregate_R, m2.aggregate_public_key, keyagg_coeff)

        psig1 = (psig_1_1 + psig_2_1) % Q

        sig = m2.signature((psig1, psig2))

        sig_bytes = bytes.fromhex(sig)
        nonce_commitment = Point.xonly_deserialize(sig_bytes[0:32].hex())
        z = int.from_bytes(sig_bytes[32:64], "big")

        # verify
        # c = H_2(R, Y, m)
        challenge_hash = Aggregator.challenge_hash(nonce_commitment, m2.aggregate_public_key, msg)
        # Negate Y if Y.y is odd
        frost_pk = pk
        musig_pk = m2.public_key
        agg_pk = m2.aggregate_public_key
        musig_nonce = m2.nonce_commitment
        if agg_pk.y % 2 != 0:
            agg_pk = -agg_pk
            frost_pk = -frost_pk
            musig_pk = -musig_pk

        if m2.aggregate_nonce_commitment.y % 2 != 0:
            R_i = -R_i
            musig_nonce = -musig_nonce

        self.assertTrue(R_i == (psig1 * G) + (Q - challenge_hash) * (keyagg_coeff * frost_pk))
        self.assertTrue(musig_nonce == (psig2 * G) + (Q - challenge_hash) * (m2.keyagg_coeff * musig_pk))

        # R ≟ g^z * Y^-c
        self.assertTrue(nonce_commitment == (z * G) + (Q - challenge_hash) * agg_pk)

        print("\nsig: ", sig)
        print("\npublic key: ", agg_pk.xonly_serialize().hex())
        print("\nmsg: ", msg.hex())
