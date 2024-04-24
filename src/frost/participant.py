"""
This module defines the Participant class for the FROST (Flexible
Round-Optimized Schnorr Threshold) signature scheme, used in distributed
cryptographic systems. It includes functionality necessary for initializing
participants, generating key shares, verifying proofs of knowledge, and
participating in the creation of a joint signature.

The Participant class represents a participant in the FROST scheme capable of
generating and handling cryptographic shares, participating in signature
creation, and verifying the integrity of the process.
"""

from hashlib import sha256
import secrets
from typing import Tuple, List
from .constants import Q
from .point import Point, G
from .aggregator import Aggregator


class Participant:
    """Class representing a FROST participant."""

    CONTEXT = b"FROST-BIP340"

    def __init__(self, index: int, threshold: int, participants: int):
        """
        Initialize a new Participant for the FROST signature scheme.

        Parameters:
        index (int): The unique index of the participant within the group.
        threshold (int): The minimum number of participants required to generate a valid signature.
        participants (int): The total number of participants in the scheme.

        Initializes storage for cryptographic coefficients, commitments, shares, and nonce pairs.
        """
        if not all(isinstance(arg, int) for arg in (index, threshold, participants)):
            raise ValueError(
                "All arguments (index, threshold, participants) must be integers."
            )

        self.index = index
        self.threshold = threshold
        self.participants = participants
        self.coefficients = None
        self.coefficient_commitments = None
        self.proof_of_knowledge = None
        self.shares = None
        self.aggregate_share = None
        self.nonce_pairs = []
        self.nonce_commitment_pairs = []
        self.public_key = None

    def init_keygen(self) -> None:
        """
        Initialize key generation for a FROST participant by setting up polynomial coefficients,
        computing a proof of knowledge, and generating coefficient commitments.
        """
        # 1. Generate polynomial with random coefficients, and with degree
        # equal to the threshold minus one.
        self._generate_polynomial()
        # 2. Compute proof of knowledge of secret a_i_0.
        self._compute_proof_of_knowledge()
        # 3. Compute coefficient commitments.
        self._compute_coefficient_commitments()

    def _generate_polynomial(self) -> None:
        """Generate random polynomial coefficients, intended for internal use."""
        # (a_i_0, . . ., a_i_(t - 1)) ⭠ $ ℤ_q
        self.coefficients = tuple(
            secrets.randbits(256) % Q for _ in range(self.threshold)
        )

    def _compute_proof_of_knowledge(self) -> None:
        """
        Compute the participant's proof of knowledge for the first coefficient,
        intended for internal use.
        """
        # k ⭠ ℤ_q
        nonce = secrets.randbits(256) % Q
        # R_i = g^k
        nonce_commitment = nonce * G
        # i
        index_byte = self.index.to_bytes(1, "big")
        # 𝚽
        context_bytes = self.CONTEXT
        # g^a_i_0
        secret = self.coefficients[0]
        secret_commitment = secret * G
        secret_commitment_bytes = secret_commitment.sec_serialize()
        # R_i
        nonce_commitment_bytes = nonce_commitment.sec_serialize()
        # c_i = H(i, 𝚽, g^a_i_0, R_i)
        challenge_hash = sha256()
        challenge_hash.update(index_byte)
        challenge_hash.update(context_bytes)
        challenge_hash.update(secret_commitment_bytes)
        challenge_hash.update(nonce_commitment_bytes)
        challenge_hash_bytes = challenge_hash.digest()
        challenge_hash_int = int.from_bytes(challenge_hash_bytes, "big")
        # μ_i = k + a_i_0 * c_i
        s = (nonce + secret * challenge_hash_int) % Q
        # σ_i = (R_i, μ_i)
        self.proof_of_knowledge = (nonce_commitment, s)

    def _compute_coefficient_commitments(self) -> None:
        """
        Compute commitments to each coefficient for verification purposes,
        intended for internal use.
        """
        # C_i = ⟨𝜙_i_0, ..., 𝜙_i_(t - 1)⟩
        # 𝜙_i_j = g^a_i_j, 0 ≤ j ≤ t - 1
        self.coefficient_commitments = tuple(
            coefficient * G for coefficient in self.coefficients
        )

    def verify_proof_of_knowledge(
        self, proof: Tuple[Point, int], secret_commitment: Point, index: int
    ) -> bool:
        """
        Verify the proof of knowledge for a given participant's commitment.

        Parameters:
        proof (Tuple[Point, int]): Contains nonce commitment (R_l) and s (μ_l).
        secret_commitment (Point): The commitment to the participant's secret.
        index (int): The participant's index.

        Returns:
        bool: True if the proof is valid, False otherwise.

        Raises:
        ValueError: If the proof format is incorrect or any parameters are invalid.
        """
        if len(proof) != 2:
            raise ValueError(
                "Proof must be a tuple containing exactly two elements (nonce commitment and s)."
            )

        # R_l, μ_l
        nonce_commitment, s = proof
        if not isinstance(nonce_commitment, Point) or not isinstance(s, int):
            raise ValueError("Proof must contain a Point and an integer.")

        # l
        index_byte = index.to_bytes(1, "big")
        # 𝚽
        context_bytes = self.CONTEXT
        # g^a_l_0
        secret_commitment_bytes = secret_commitment.sec_serialize()
        nonce_commitment_bytes = nonce_commitment.sec_serialize()
        # c_l = H(l, 𝚽, g^a_l_0, R_l)
        challenge_input = (
            index_byte
            + context_bytes
            + secret_commitment_bytes
            + nonce_commitment_bytes
        )
        challenge_hash = sha256(challenge_input).digest()
        challenge_hash_int = int.from_bytes(challenge_hash, "big")
        # R_l ≟ g^μ_l * 𝜙_l_0^-c_l, 1 ≤ l ≤ n, l ≠ i
        expected_nonce_commitment = (s * G) + (
            (Q - challenge_hash_int) * secret_commitment
        )
        return nonce_commitment == expected_nonce_commitment

    def generate_shares(self):
        """
        Generate shares for each participant based on the previously defined polynomial.

        Each share corresponds to the polynomial evaluated at the participant's index.
        Shares are immutable once generated to ensure security and integrity.
        """
        if not self.coefficients:
            raise ValueError(
                "Polynomial coefficients must be initialized before generating shares."
            )

        # (i, f_i(i)), (l, f_i(l))
        self.shares = tuple(
            self._evaluate_polynomial(x) for x in range(1, self.participants + 1)
        )

    def _evaluate_polynomial(self, x: int) -> int:
        """
        Evaluate the polynomial at a given point x using Horner's method.

        Parameters:
        x (int): The point at which the polynomial is evaluated.

        Returns:
        int: The value of the polynomial at x, reduced modulo Q.

        Raises:
        ValueError: If x is not an integer.
        """
        if not isinstance(x, int):
            raise ValueError("The value of x must be an integer.")

        y = 0
        for coefficient in reversed(self.coefficients):
            y = (y * x + coefficient) % Q
        return y

    def _lagrange_coefficient(self, participant_indexes: List[int]) -> int:
        """
        Calculate the Lagrange coefficient for this participant relative to other participants.

        Parameters:
        participant_indexes (List[int]): A list of indices of other
        participants involved in the calculation.

        Returns:
        int: The Lagrange coefficient used in polynomial reconstruction or signature generation.

        Raises:
        ValueError: If duplicate indices are found.
        """

        if len(participant_indexes) != len(set(participant_indexes)):
            raise ValueError("Participant indexes must be unique.")

        # λ_i = ∏ p_j/(p_j - p_i), 1 ≤ j ≤ α, j ≠ i
        numerator = 1
        denominator = 1
        for index in participant_indexes:
            if index == self.index:
                continue
            numerator = numerator * index
            denominator = denominator * (index - self.index)
        return (numerator * pow(denominator, Q - 2, Q)) % Q

    def verify_share(
        self, y: Point, coefficient_commitments: List[Point], threshold: int
    ) -> bool:
        """
        Verify that a given share matches the expected value derived from coefficient commitments.

        Parameters:
        y (Point): The share to verify.
        coefficient_commitments (List[Point]): The commitments of the coefficients.
        threshold (int): The number of required commitments.

        Returns:
        bool: True if the share is valid according to the commitments, False otherwise.

        Raises:
        ValueError: If the number of coefficient commitments does not match the threshold.
        """
        if len(coefficient_commitments) != threshold:
            raise ValueError(
                "The number of coefficient commitments must match the threshold."
            )

        # ∏ 𝜙_l_k^i^k mod q, 0 ≤ k ≤ t - 1
        expected_y_commitment = Point(float("inf"), float("inf"))  # Point at infinity
        for k, commitment in enumerate(coefficient_commitments):
            expected_y_commitment += (self.index**k % Q) * commitment

        # g^f_l(i) ≟ ∏ 𝜙_l_k^i^k mod q, 0 ≤ k ≤ t - 1
        return y * G == expected_y_commitment

    def aggregate_shares(self, other_shares: List[int]) -> None:
        """
        Aggregate the shares from all participants to compute the participant's aggregate share.

        Parameters:
        other_shares (List[int]): A list of integer shares from other participants.

        This method updates the participant's aggregate share based on the provided shares and
        the participant's own share.
        """
        if not self.shares:
            raise ValueError("Participant's shares have not been initialized.")
        if not 0 <= self.index - 1 < len(self.shares):
            raise ValueError("Participant index is out of range.")

        # s_i = ∑ f_l(i), 1 ≤ l ≤ n
        aggregate_share = self.shares[self.index - 1]
        for other_share in other_shares:
            if not isinstance(other_share, int):
                raise TypeError("All shares must be integers.")
            aggregate_share = (aggregate_share + other_share) % Q

        self.aggregate_share = aggregate_share

    def public_verification_share(self) -> Point:
        """
        Compute the public verification share from the participant's aggregate share.

        Returns:
        Point: The public verification share as a point on the elliptic curve.

        Raises:
        AttributeError: If the aggregate share is not properly initialized.
        """
        if self.aggregate_share is None:
            raise AttributeError("Aggregate share has not been initialized.")

        # Y_i = g^s_i
        return self.aggregate_share * G

    def derive_public_key(self, other_secret_commitments: List[Point]) -> Point:
        """
        Derive the public key by summing up the secret commitments.

        Parameters:
        other_secret_commitments (List[Point]): A list of secret commitments
        from other participants.

        Returns:
        Point: The derived public key as a point on the elliptic curve.

        Raises:
        ValueError: If the coefficient commitments are not initialized or are empty.
        """
        if not self.coefficient_commitments:
            raise ValueError(
                "Coefficient commitments have not been initialized or are empty."
            )

        # Y = ∏ 𝜙_j_0, 1 ≤ j ≤ n
        public_key = self.coefficient_commitments[0]
        for other_secret_commitment in other_secret_commitments:
            if not isinstance(other_secret_commitment, Point):
                raise TypeError("All secret commitments must be Point instances.")
            public_key += other_secret_commitment

        self.public_key = public_key
        return public_key

    def generate_nonces(self, amount: int) -> None:
        """
        Generate a specified amount of nonce pairs and their elliptic curve
        commitments for cryptographic operations.

        Parameters:
        amount (int): The number of nonce pairs to generate.

        Raises:
        ValueError: If the specified amount is not a positive integer.
        """
        if not isinstance(amount, int) or amount <= 0:
            raise ValueError("Amount must be a positive integer.")

        # Preprocess(π) ⭢  (i, ⟨(D_i_j, E_i_j)⟩), 1 ≤ j ≤ π
        for _ in range(amount):
            # (d_i_j, e_i_j) ⭠ $ ℤ*_q x ℤ*_q
            nonce_pair = (secrets.randbits(256) % Q, secrets.randbits(256) % Q)
            # (D_i_j, E_i_j) = (g^d_i_j, g^e_i_j)
            nonce_commitment_pair = (nonce_pair[0] * G, nonce_pair[1] * G)

            self.nonce_pairs.append(nonce_pair)
            self.nonce_commitment_pairs.append(nonce_commitment_pair)

    def sign(
        self,
        message: bytes,
        nonce_commitment_pairs: List[Tuple[Point, Point]],
        participant_indexes: List[int],
    ) -> int:
        """
        Generate a signature contribution for this participant.

        Parameters:
        message (bytes): The message being signed.
        nonce_commitment_pairs (List[Tuple[Point, Point]]): List of tuples of nonce commitments.
        participant_indexes (List[int]): List of participant indexes involved in the signing.

        Returns:
        int: The signature share of this participant.

        Raises:
        ValueError: If required cryptographic elements are not properly initialized.
        """
        if not self.nonce_pairs:
            raise ValueError("Nonce pairs are empty. Cannot proceed with signing.")
        # R
        group_commitment = Aggregator.group_commitment(
            message, nonce_commitment_pairs, participant_indexes
        )

        # c = H_2(R, Y, m)
        challenge_hash = Aggregator.challenge_hash(
            group_commitment, self.public_key, message
        )

        nonce_pair = self.nonce_pairs.pop()
        # d_i, e_i
        first_nonce, second_nonce = nonce_pair

        # Negate d_i and e_i if R is odd
        if group_commitment.y % 2 != 0:
            first_nonce = Q - first_nonce
            second_nonce = Q - second_nonce

        # p_i = H_1(i, m, B), i ∈ S
        binding_value = Aggregator.binding_value(
            self.index, message, nonce_commitment_pairs, participant_indexes
        )
        # λ_i
        lagrange_coefficient = self._lagrange_coefficient(participant_indexes)
        # s_i
        aggregate_share = self.aggregate_share

        # Negate s_i if Y is odd
        if self.public_key.y % 2 != 0:
            aggregate_share = Q - aggregate_share

        # z_i = d_i + (e_i * p_i) + λ_i * s_i * c
        return (
            first_nonce
            + (second_nonce * binding_value)
            + lagrange_coefficient * aggregate_share * challenge_hash
        ) % Q
