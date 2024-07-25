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

from typing import Tuple, Optional
from hashlib import sha256
from .point import Point, G
from .constants import Q


class Aggregator:
    """Class representing the signature aggregator."""

    def __init__(
        self,
        public_key: Point,
        message: bytes,
        nonce_commitment_pairs: Tuple[Tuple[Point, Point], ...],
        participant_indexes: Tuple[int, ...],
        bip32_tweak: Optional[int] = None,
        taproot_tweak: Optional[int] = None,
    ):
        """
        Initialize the Aggregator for managing and processing cryptographic
        elements in the FROST signature scheme.

        Parameters:
        public_key (Point): The public key used in the signature verification process.
        message (bytes): The message that is being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): A tuple of
            nonce commitments from each participant.
        participant_indexes (Tuple[int, ...]): Indices of participants involved in the signature process.
        bip32_tweak (Optional[int]): Optional BIP32 tweak value for key tweaking.
        taproot_tweak (Optional[int]): Optional Taproot tweak value for key tweaking.

        Raises:
        ValueError: If only one tweak (either bip32_tweak or taproot_tweak) is provided.
                    Both or neither must be provided.

        This setup prepares the Aggregator to handle the aggregation of nonce
        commitments and signatures.
        """
        # Y
        self.public_key = public_key
        # m
        self.message = message
        # B
        self.nonce_commitment_pairs = nonce_commitment_pairs
        # S = α: t ≤ α ≤ n
        self.participant_indexes = participant_indexes

        self.tweaked_key = None
        self.tweak = None

        if (bip32_tweak is None) != (taproot_tweak is None):
            raise ValueError(
                "Both bip32_tweak and taproot_tweak must be provided together, or neither."
            )

        if bip32_tweak is not None and taproot_tweak is not None:
            tweaked_key, tweak, _ = self._compute_tweaks(
                bip32_tweak, taproot_tweak, public_key
            )
            self.tweaked_key = tweaked_key
            self.tweak = tweak

    @classmethod
    def tweak_key(
        cls, bip32_tweak: int, taproot_tweak: int, public_key: Point
    ) -> Tuple[Point, int]:
        tweaked_key, _, p = cls._compute_tweaks(bip32_tweak, taproot_tweak, public_key)
        return tweaked_key, p

    @classmethod
    def group_commitment(
        cls,
        message: bytes,
        nonce_commitment_pairs: Tuple[Tuple[Point, Point], ...],
        participant_indexes: Tuple[int, ...],
    ) -> Point:
        """
        Calculate the group commitment by aggregating individual commitments from participants.

        Parameters:
        message (bytes): The message being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): A tuple containing pairs of
        nonce commitments for each participant.
        participant_indexes (Tuple[int, ...]): Indices of participants involved in the signature,
        expected to start from 1.

        Returns:
        Point: The aggregated group commitment as a point on the elliptic curve.

        Raises:
        ValueError: If any participant index is out of the expected range.
        """
        # R
        group_commitment = Point()  # Point at infinity
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
        nonce_commitment_pairs: Tuple[Tuple[Point, Point], ...],
        participant_indexes: Tuple[int, ...],
    ) -> int:
        """
        Compute a binding value used in cryptographic operations, uniquely
        identifying participant contributions.

        Parameters: index (int): The index of the participant. message (bytes):
        The message being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): A list of nonce commitments
        for each participant.
        participant_indexes (Tuple[int, ...]): The indices of participants involved
        in the operation.

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

    @classmethod
    def derive_shared_secret(cls, shared_secret_shares: Tuple[Point, ...]) -> Point:
        """
        Derive the shared secret from the aggregated shared secret shares.

        Parameters:
        shared_secret_shares (Tuple[Point, ...]): Tuple of shared secret shares
        from all participating members.

        Returns:
        Point: The derived shared secret as a point on the elliptic curve.
        """
        # K = ∑ K_i, i ∈ S
        shared_secret = Point()
        for shared_secret_share in shared_secret_shares:
            shared_secret += shared_secret_share

        return shared_secret

    def signing_inputs(self) -> Tuple[bytes, Tuple[Tuple[Point, Point], ...]]:
        """
        Returns the signing inputs to be used by the signers.

        Returns:
        Tuple[bytes, Tuple[Tuple[Point, Point], ...]]: A tuple containing the
        message and the list of nonce commitments organized by participant
        indices.
        """
        # B = ⟨(i, D_i, E_i)⟩_i∈S
        # (m, B)
        return (self.message, self.nonce_commitment_pairs)

    def signature(self, signature_shares: Tuple[int, ...]) -> str:
        """
        Compute the final signature from the aggregated signature shares.

        Parameters:
        signature_shares (Tuple[int, ...]): Tuple of signature shares from all participating members.

        Returns:
        str: The final signature in hexadecimal format.
        """
        # R
        group_commitment = self.group_commitment(
            self.message, self.nonce_commitment_pairs, self.participant_indexes
        )
        nonce_commitment = group_commitment.xonly_serialize()

        # TODO: verify each signature share
        z = sum(signature_shares) % Q

        if self.tweak and self.tweaked_key:
            challenge_hash = self.challenge_hash(
                group_commitment, self.tweaked_key, self.message
            )
            z = (z + (challenge_hash * self.tweak)) % Q

        # σ = (R, z)
        return (nonce_commitment + z.to_bytes(32, "big")).hex()

    @classmethod
    def _compute_tweaks(
        cls, bip32_tweak: int, taproot_tweak: int, public_key: Point
    ) -> Tuple[Point, int, int]:
        """
        Compute the tweaked keys and adjustments for the given BIP32 and Taproot tweaks.

        This method derives a tweaked public key and calculates the corresponding
        adjusted tweaks for use in cryptographic operations. It ensures that the
        derived keys are valid and handles odd parity cases by adjusting the
        tweaks accordingly.

        Parameters:
        bip32_tweak (int): The BIP32 tweak value to adjust the public key.
        taproot_tweak (int): The Taproot tweak value to adjust the public key.
        public_key (Point): The initial public key used as the base for tweaking.

        Returns:
        Tuple[Point, int, int]: A tuple containing the aggregate tweaked key (Point),
                                the adjusted aggregate tweak (int), and the BIP32 key
                                parity (int).

        Raises:
        ValueError: If the resulting tweaked public key is invalid.
        """
        # Derive the BIP32 child key
        bip32_key = public_key + (bip32_tweak * G)
        if bip32_key.y is None:
            raise ValueError("Invalid public key.")
        is_bip32_key_odd = bip32_key.y % 2 != 0
        # Derive the x-only key
        if is_bip32_key_odd:
            bip32_key = -bip32_key
        # Track the parity
        bip32_parity = 1 if is_bip32_key_odd else 0
        # Adjust the tweak if the key is odd
        adjusted_bip32_tweak = -bip32_tweak if is_bip32_key_odd else bip32_tweak

        # Add the taproot key
        aggregate_key = bip32_key + (taproot_tweak * G)
        if aggregate_key.y is None:
            raise ValueError("Invalid public key.")
        # Aggregate the tweaks
        aggregate_tweak = (adjusted_bip32_tweak + taproot_tweak) % Q
        # Adjust the aggregate tweak if the key is odd
        adjusted_aggregate_tweak = (
            (-aggregate_tweak) % Q if aggregate_key.y % 2 != 0 else aggregate_tweak
        )

        return aggregate_key, adjusted_aggregate_tweak, bip32_parity
