"""
This module defines the Aggregator class used in the FROST (Flexible
Round-Optimized Schnorr Threshold) signature scheme. The Aggregator is
responsible for coordinating and processing the cryptographic elements
necessary to construct a joint signature from multiple participants.

The Aggregator class handles the aggregation of signatures, nonce commitments,
and other cryptographic elements to facilitate the generation of a threshold
signature. It ensures that all components are correctly combined according to
the FROST protocol.
"""

from typing import List, Tuple
from hashlib import sha256
from .point import Point
from .constants import Q


class Aggregator:
    """Class representing the signature aggregator."""

    def __init__(
        self,
        public_key: Point,
        message: bytes,
        nonce_commitment_pair_list: List[Point],
        participant_indexes: Tuple[int],
    ):
        """
        Initialize the Aggregator for managing and processing cryptographic
        elements in the FROST signature scheme.

        Parameters:
        public_key (Point): The public key used in the signature verification process.
        message (bytes): The message that is being signed.
        nonce_commitment_pair_list (List[Point]): A list of nonce commitments from each participant.
        participant_indexes (Tuple[int]): Indices of participants involved in the signature process.

        This setup prepares the Aggregator to handle the aggregation of nonce
        commitments and signatures.
        """
        # Y
        self.public_key = public_key
        # m
        self.message = message
        # L
        self.nonce_commitment_pair_list = nonce_commitment_pair_list
        # S = α: t ≤ α ≤ n
        self.participant_indexes = participant_indexes
        # B
        self.nonce_commitment_pairs = None

    @classmethod
    def group_commitment(
        cls,
        message: bytes,
        nonce_commitment_pairs: List[List[Point]],
        participant_indexes: List[int],
    ) -> Point:
        """
        Calculate the group commitment by aggregating individual commitments from participants.

        Parameters:
        message (bytes): The message being signed.
        nonce_commitment_pairs (List[List[Point]]): A list containing pairs of
        nonce commitments for each participant. participant_indexes
        (List[int]): Indices of participants involved in the signature,
        expected to start from 1.

        Returns:
        Point: The aggregated group commitment as a point on the elliptic curve.

        Raises:
        ValueError: If any participant index is out of the expected range.
        """
        # R
        group_commitment = Point(x=float("inf"), y=float("inf"))  # Point at infinity
        for index in participant_indexes:
            if index < 1 or index > len(nonce_commitment_pairs):
                raise ValueError(f"Participant index {index} is out of range.")

            # p_l = H_1(l, m, B), l ∈ S
            binding_value = cls.binding_value(
                index, message, nonce_commitment_pairs, participant_indexes
            )
            # D_l, E_l
            first_commitment, second_commitment = nonce_commitment_pairs[index - 1]

            # R = ∏ D_l * (E_l)^p_l, l ∈ S
            group_commitment += first_commitment + (binding_value * second_commitment)

        return group_commitment

    @classmethod
    def binding_value(
        cls,
        index: int,
        message: bytes,
        nonce_commitment_pairs: List[List[Point]],
        participant_indexes: List[int],
    ) -> int:
        """
        Compute a binding value used in cryptographic operations, uniquely
        identifying participant contributions.

        Parameters: index (int): The index of the participant. message (bytes):
        The message being signed. nonce_commitment_pairs (List[List[Point]]): A
        list of nonce commitments for each participant. participant_indexes
        (List[int]): The indices of participants involved in the operation.

        Returns: int: The resulting binding value as an integer.

        Raises:
        ValueError: If any index is out of the expected range.
        """
        if index < 1:
            raise ValueError("Participant index must start from 1.")

        binding_value = sha256()
        # l
        index_byte = index.to_bytes(1, "big")

        # B
        nonce_commitment_pairs_bytes = []
        for idx in participant_indexes:
            if idx < 1 or idx > len(nonce_commitment_pairs):
                raise ValueError(f"Index {idx} is out of range for nonce commitments.")
            participant_pair = nonce_commitment_pairs[idx - 1]
            participant_pair_bytes = b"".join(
                [commitment.sec_serialize() for commitment in participant_pair]
            )
            nonce_commitment_pairs_bytes.append(participant_pair_bytes)

        # p_l = H_1(l, m, B), l ∈ S
        binding_value.update(index_byte)
        binding_value.update(message)
        binding_value.update(b"".join(nonce_commitment_pairs_bytes))
        binding_value_bytes = binding_value.digest()

        return int.from_bytes(binding_value_bytes, "big")

    @classmethod
    def challenge_hash(
        cls, nonce_commitment: Point, public_key: Point, message: bytes
    ) -> int:
        """
        Compute the challenge hash used in cryptographic operations, binding
        the nonce commitment, public key, and message.

        Parameters:
        nonce_commitment (Point): The nonce commitment point.
        public_key (Point): The public key point.
        message (bytes): The message involved in the operation.

        Returns:
        int: The resulting challenge hash value as an integer, reduced by modulo Q.
        """
        # c = H_2(R, Y, m)
        tag_hash = sha256(b"BIP0340/challenge").digest()
        challenge_hash = sha256()
        challenge_hash.update(tag_hash)
        challenge_hash.update(tag_hash)
        challenge_hash.update(nonce_commitment.xonly_serialize())
        challenge_hash.update(public_key.xonly_serialize())
        challenge_hash.update(message)
        challenge_hash_bytes = challenge_hash.digest()

        return int.from_bytes(challenge_hash_bytes, "big") % Q

    def signing_inputs(self) -> Tuple[bytes, List[Point]]:
        """
        Prepare the signing inputs by organizing nonce commitments for each participant.

        Returns:
        Tuple[bytes, List[Point]]: A tuple containing the message and the list of nonce commitments
        organized by participant indexes.

        Raises:
        IndexError: If any participant's commitment list is empty.
        """
        # B = ⟨(i, D_i, E_i)⟩_i∈S
        nonce_commitment_pairs = [None] * max(self.participant_indexes)
        # P_i ∈ S
        for index in self.participant_indexes:
            # L_i
            participant_pairs = self.nonce_commitment_pair_list[index - 1]
            if not participant_pairs:
                raise IndexError(
                    f"No available commitments left for participant index {index}."
                )
            nonce_commitment_pairs[index - 1] = participant_pairs.pop()

        self.nonce_commitment_pairs = nonce_commitment_pairs
        # (m, B)
        return (self.message, nonce_commitment_pairs)

    def signature(self, signature_shares: List[int]) -> str:
        """
        Compute the final signature from the aggregated signature shares.

        Parameters:
        signature_shares (List[int]): The list of signature shares from all participating members.

        Returns:
        str: The final signature in hexadecimal format.
        """
        # R
        group_commitment = self.group_commitment(
            self.message, self.nonce_commitment_pairs, self.participant_indexes
        )
        nonce_commitment = group_commitment.xonly_serialize()

        # TODO: verify each signature share
        z = (sum(signature_shares) % Q).to_bytes(32, "big")

        # σ = (R, z)
        return (nonce_commitment + z).hex()
