"""
This module defines the Aggregator class used in the FROST (Flexible
Round-Optimized Schnorr Threshold) signature scheme. The Aggregator is
responsible for coordinating and processing the cryptographic elements
necessary to construct a joint signature from multiple participants.

The Aggregator class handles the aggregation of signatures, nonce commitments,
and other cryptographic elements to facilitate the generation of a threshold
signature. It ensures that all components are correctly combined according to
the FROST protocol.

References:
- Komlo, C. and Goldberg, I., "FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures," SAC 2020, LNCS 12804, pp. 34-65.
- BIP 340: Schnorr Signatures for secp256k1 (Wuille, Nick, Ruffing).
- BIP 341: Taproot: SegWit version 1 spending rules.
- BIP 327: MuSig2 for BIP340-Compatible Multi-Signatures (Nick, Ruffing,
  Seurin). (Key tweaking approach adapted for threshold signatures.)
- BIP 32: Hierarchical Deterministic Wallets (Wuille).
"""

from hashlib import sha256

from .constants import Q
from .keygen import derive_public_verification_share
from .lagrange import lagrange_coefficient
from .point import G, Point
from .tagged_hash import tagged_hash


class Aggregator:
    """Class representing the signature aggregator."""

    def __init__(
        self,
        public_key: Point,
        message: bytes,
        nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
        participant_indexes: tuple[int, ...],
        bip32_tweak: int | None = None,
        taproot_tweak: int | None = None,
        group_commitments: tuple[Point, ...] | None = None,
    ):
        """
        Initialize the Aggregator for managing and processing cryptographic
        elements in the FROST signature scheme.

        Parameters:
        public_key (Point): The public key used in the signature verification process.
        message (bytes): The message that is being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): A tuple of
            nonce commitments from each participant.
        participant_indexes (Tuple[int, ...]): Indices of participants involved in the
            signature process.
        bip32_tweak (Optional[int]): Optional BIP32 tweak value for key tweaking.
        taproot_tweak (Optional[int]): Optional Taproot tweak value for key tweaking.
        group_commitments (Optional[Tuple[Point, ...]]): Group commitments for
            signature share verification. If provided, each share is verified
            before aggregation.

        Raises:
        ValueError: If only one tweak (either bip32_tweak or taproot_tweak) is provided.
                    Both or neither must be provided.
        """
        # Y
        self.public_key = public_key
        # m
        self.message = message
        # B
        self.nonce_commitment_pairs = nonce_commitment_pairs
        # S = α: t ≤ α ≤ n
        self.participant_indexes = participant_indexes
        self.group_commitments = group_commitments
        self.bip32_tweak = bip32_tweak
        self.taproot_tweak = taproot_tweak

        self.tweaked_key = None
        self.tweak = None

        if (bip32_tweak is None) != (taproot_tweak is None):
            raise ValueError(
                "Both bip32_tweak and taproot_tweak must be provided together, or neither."
            )

        if bip32_tweak is not None and taproot_tweak is not None:
            tweaked_key, tweak, _ = self._compute_tweaks(bip32_tweak, taproot_tweak, public_key)
            self.tweaked_key = tweaked_key
            self.tweak = tweak

    @classmethod
    def tweak_key(
        cls, bip32_tweak: int, taproot_tweak: int, public_key: Point
    ) -> tuple[Point, int]:
        tweaked_key, _, p = cls._compute_tweaks(bip32_tweak, taproot_tweak, public_key)
        return tweaked_key, p

    @classmethod
    def group_commitment(
        cls,
        message: bytes,
        nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
        participant_indexes: tuple[int, ...],
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

            # ρₗ = H₁(l, m, B), l ∈ S
            binding_value = cls.binding_value(
                index, message, nonce_commitment_pairs, participant_indexes
            )
            # Dₗ, Eₗ
            first_commitment, second_commitment = nonce_commitment_pairs[index - 1]

            # R = ∏ Dₗ · (Eₗ)^ρₗ, l ∈ S
            group_commitment += first_commitment + (binding_value * second_commitment)

        return group_commitment

    @classmethod
    def binding_value(
        cls,
        index: int,
        message: bytes,
        nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
        participant_indexes: tuple[int, ...],
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
                [commitment.to_bytes_compressed() for commitment in participant_pair]
            )
            nonce_commitment_pairs_bytes.append(participant_pair_bytes)

        # ρₗ = H₁(l, m, B), l ∈ S
        binding_value.update(index_byte)
        binding_value.update(message)
        binding_value.update(b"".join(nonce_commitment_pairs_bytes))
        binding_value_bytes = binding_value.digest()

        # Note: the binding value is NOT reduced mod Q here. The raw 256-bit
        # hash output is used directly as a scalar coefficient. This is correct
        # because scalar multiplication (binding_value * second_commitment)
        # reduces mod Q implicitly in Point.__rmul__.
        #
        # Limitation: participant index is encoded as a single byte, limiting
        # indexes to 0-255. Sufficient for educational use.
        return int.from_bytes(binding_value_bytes, "big")

    @classmethod
    def challenge_hash(cls, nonce_commitment: Point, public_key: Point, message: bytes) -> int:
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
        # c = H₂(R, Y, m)
        challenge_bytes = tagged_hash(
            "BIP0340/challenge",
            nonce_commitment.to_bytes_xonly() + public_key.to_bytes_xonly() + message,
        )
        # Reduce the 256-bit hash to a scalar in the curve order field
        return int.from_bytes(challenge_bytes, "big") % Q

    @classmethod
    def derive_shared_secret(cls, shared_secret_shares: tuple[Point, ...]) -> Point:
        """
        Derive the shared secret from the aggregated shared secret shares.

        Parameters:
        shared_secret_shares (Tuple[Point, ...]): Tuple of shared secret shares
        from all participating members.

        Returns:
        Point: The derived shared secret as a point on the elliptic curve.
        """
        # K = ∑ Kᵢ, i ∈ S
        shared_secret = Point()
        for shared_secret_share in shared_secret_shares:
            shared_secret += shared_secret_share

        return shared_secret

    def signing_inputs(self) -> tuple[bytes, tuple[tuple[Point, Point], ...]]:
        """
        Returns the signing inputs to be used by the signers.

        Returns:
        Tuple[bytes, Tuple[Tuple[Point, Point], ...]]: A tuple containing the
        message and the list of nonce commitments organized by participant
        indices.
        """
        # B = ⟨(i, Dᵢ, Eᵢ)⟩_i∈S
        # (m, B)
        return (self.message, self.nonce_commitment_pairs)

    @classmethod
    def verify_signature_share(
        cls,
        share: int,
        participant_index: int,
        participant_indexes: tuple[int, ...],
        group_commitment: Point,
        public_key: Point,
        nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
        message: bytes,
        public_verification_share: Point,
        bip32_tweak: int | None = None,
        taproot_tweak: int | None = None,
    ) -> bool:
        """Verify an individual signature share before aggregation.

        This catches a misbehaving signer before their invalid share corrupts
        the aggregate signature. Without this check, a single bad share
        produces an invalid group signature with no way to identify the culprit.

        Verification equation:
            zᵢ·G == Rᵢ_adj + c·λᵢ·Yᵢ_adj
        """
        # 1. Compute binding value: ρᵢ = H₁(i, m, B)
        rho_i = cls.binding_value(
            participant_index, message, nonce_commitment_pairs, participant_indexes
        )

        # 2. Compute participant's nonce contribution: Rᵢ = Dᵢ + ρᵢ·Eᵢ
        pos = participant_indexes.index(participant_index)
        D_i, E_i = nonce_commitment_pairs[pos]
        R_i = D_i + (rho_i * E_i)

        # 3. Negate Rᵢ if group commitment has odd y
        assert group_commitment.y is not None
        if group_commitment.y % 2 != 0:
            R_i = -R_i

        # 4. Compute effective key and challenge hash (handle tweaks like sign does)
        tweaked_key = public_key
        parity = 0
        if bip32_tweak is not None and taproot_tweak is not None:
            tweaked_key, parity = cls.tweak_key(bip32_tweak, taproot_tweak, public_key)

        challenge = cls.challenge_hash(group_commitment, tweaked_key, message)

        # 5. Compute Lagrange coefficient
        lam = lagrange_coefficient(participant_indexes, participant_index)

        # 6. Adjust Yᵢ for key parity: negate if effective key has odd y
        Y_i = public_verification_share
        if tweaked_key.y is None:
            raise ValueError("Public key is the point at infinity.")
        if tweaked_key.y % 2 != parity:
            Y_i = -Y_i

        # 7. Check: zᵢ·G == Rᵢ_adj + (c·λᵢ)·Yᵢ_adj
        return share * G == R_i + (challenge * int(lam)) * Y_i

    def signature(self, signature_shares: tuple[int, ...]) -> str:
        """
        Compute the final signature from the aggregated signature shares.

        Parameters:
        signature_shares (Tuple[int, ...]): Tuple of signature shares from all
            participating members.

        Returns:
        str: The final signature in hexadecimal format.
        """
        # R
        group_commitment = self.group_commitment(
            self.message, self.nonce_commitment_pairs, self.participant_indexes
        )
        nonce_commitment = group_commitment.to_bytes_xonly()

        # Verify each signature share if group_commitments are available
        if self.group_commitments is not None:
            for share, index in zip(signature_shares, self.participant_indexes, strict=True):
                Y_i = derive_public_verification_share(self.group_commitments, index)
                if not self.verify_signature_share(
                    share,
                    index,
                    self.participant_indexes,
                    group_commitment,
                    self.public_key,
                    self.nonce_commitment_pairs,
                    self.message,
                    Y_i,
                    self.bip32_tweak,
                    self.taproot_tweak,
                ):
                    raise ValueError(f"Invalid signature share from participant {index}.")

        # Aggregate signature: z = ∑ zᵢ (mod Q, the curve order)
        z = sum(signature_shares) % Q

        if self.tweak and self.tweaked_key:
            challenge_hash = self.challenge_hash(group_commitment, self.tweaked_key, self.message)
            # Add tweak correction to the aggregate signature (scalar arithmetic mod Q)
            z = (z + (challenge_hash * self.tweak)) % Q

        # σ = (R, z)
        return (nonce_commitment + z.to_bytes(32, "big")).hex()

    @classmethod
    def _compute_tweaks(
        cls, bip32_tweak: int, taproot_tweak: int, public_key: Point
    ) -> tuple[Point, int, int]:
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
        # Aggregate the tweaks (scalar addition mod curve order)
        aggregate_tweak = (adjusted_bip32_tweak + taproot_tweak) % Q
        # Negate the aggregate tweak if the key has odd y (scalar negation: -x = (-x) mod Q)
        adjusted_aggregate_tweak = (
            (-aggregate_tweak) % Q if aggregate_key.y % 2 != 0 else aggregate_tweak
        )

        return aggregate_key, adjusted_aggregate_tweak, bip32_parity
