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
from typing import Tuple, Optional, List
from .constants import Q
from .point import Point, G
from .aggregator import Aggregator
from .matrix import Matrix


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

        Raises:
        ValueError: If any of the arguments are not integers.
        """
        if not all(isinstance(arg, int) for arg in (index, threshold, participants)):
            raise ValueError(
                "All arguments (index, threshold, participants) must be integers."
            )

        self.index = index
        self.threshold = threshold
        self.participants = participants
        self.coefficients: Optional[Tuple[int, ...]] = None
        self.coefficient_commitments: Optional[Tuple[Point, ...]] = None
        self.proof_of_knowledge: Optional[Tuple[Point, int]] = None
        self.shares: Optional[Tuple[int, ...]] = None
        self.aggregate_share: Optional[int] = None
        self.nonce_pair: Optional[Tuple[int, int]] = None
        self.nonce_commitment_pair: Optional[Tuple[Point, Point]] = None
        self.public_key: Optional[Point] = None
        self.repair_shares: Optional[Tuple[Optional[int], ...]] = None
        self.aggregate_repair_share: Optional[int] = None
        self.repair_share_commitments: Optional[Tuple[Optional[Point], ...]] = None
        self.group_commitments: Optional[Tuple[Point, ...]] = None
        self.repair_participants: Optional[Tuple[int, ...]] = None

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

    def init_refresh(self) -> None:
        """
        Initialize proactive secret sharing refresh for a participant by generating a new polynomial
        with random coefficients and computing new coefficient commitments.
        """
        # 1. Generate polynomial with random coefficients, and with degree
        # equal to the threshold minus one, with the first coefficient set to 0.
        self._generate_refresh_polynomial()
        # 2. Compute coefficient commitments.
        self._compute_coefficient_commitments()

    def init_threshold_increase(self, new_threshold: int) -> None:
        """
        Initializes the process to increase the threshold in a threshold cryptography scheme.

        This method is responsible for generating a new polynomial with a degree corresponding
        to the new threshold, computing proof of knowledge for security purposes, and computing
        new coefficient commitments based on the new polynomial. It updates the internal state
        to reflect the new threshold value.

        Parameters:
        new_threshold (int): The new threshold value which must be an integer greater than the
        current threshold.

        Raises:
        ValueError: If the new_threshold is not an integer or if it is not greater than the
        current threshold.
        """
        if not isinstance(new_threshold, int):
            raise ValueError("New threshold must be an integer.")
        if new_threshold <= self.threshold:
            raise ValueError(
                "New threshold must be greater than the current threshold."
            )

        self._generate_threshold_increase_polynomial(new_threshold)
        self._compute_proof_of_knowledge()
        self._compute_coefficient_commitments()

        self.threshold = new_threshold

    def _generate_polynomial(self) -> None:
        """Generate random polynomial coefficients."""
        # (a_i_0, . . ., a_i_(t - 1)) ⭠ $ ℤ_q
        self.coefficients = tuple(
            secrets.randbits(256) % Q for _ in range(self.threshold)
        )

    def _generate_refresh_polynomial(self) -> None:
        """
        Generate a polynomial with random coefficients for proactive secret
        sharing refresh, where the first coefficient is set to 0 to ensure the
        refresh does not change the shared secret.
        """
        # Generate the rest of the coefficients randomly, except the first one which is set to 0.
        # (a_i_0, . . ., a_i_(t - 1)) ⭠ $ ℤ_q
        # a_i_0 is set to 0 explicitly.
        self.coefficients = (0,) + tuple(
            secrets.randbits(256) % Q for _ in range(self.threshold - 1)
        )

    def _generate_threshold_increase_polynomial(self, new_threshold: int) -> None:
        """
        Generate a polynomial with random coefficients for increasing the
        threshold, with a degree equal to the threshold minus two.

        Parameters:
        new_threshold (int): The new threshold value which must be an integer greater than the
        current threshold.
        """
        self.coefficients = tuple(
            secrets.randbits(256) % Q for _ in range(new_threshold - 1)
        )

    def _compute_proof_of_knowledge(self) -> None:
        """
        Compute the participant's proof of knowledge for the first coefficient,
        """
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")

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
        """
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")

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

    def generate_repair_shares(
        self, repair_participants: Tuple[int, ...], index: int
    ) -> None:
        """
        Generate repair shares and commitments to assist a participant in
        recovering a lost share.

        Parameters:
        repair_participants (Tuple[int, ...]): Indices of participants involved in the repair.
        index (int): The index of the participant with the lost share.

        Raises:
        ValueError: If the aggregate share has not been initialized.
        """
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")

        lagrange_coefficient = self._lagrange_coefficient(repair_participants, index)
        random_shares = tuple(
            secrets.randbits(256) % Q for _ in range(self.threshold - 1)
        )
        final_share = (
            (lagrange_coefficient * self.aggregate_share) - sum(random_shares)
        ) % Q

        self.repair_shares = random_shares + (final_share,)
        self.repair_share_commitments = tuple(share * G for share in self.repair_shares)
        self.repair_participants = tuple(sorted(repair_participants + (self.index,)))

    def get_repair_share(self, participant_index):
        """
        Retrieves the repair share for the given participant index.

        Parameters:
        participant_index (int): The index of the participant.

        Returns:
        The repair share associated with the given participant index.

        Raises:
        IndexError: If the participant_index is out of the range of the repair shares.
        """
        # Check if the index is in the set of repair participants
        if participant_index not in self.repair_participants:
            raise IndexError("Participant index does not match the initial set.")

        mapped_index = self.repair_participants.index(participant_index)
        return self.repair_shares[mapped_index]

    def get_repair_share_commitment(
        self,
        participant_index,
        repair_share_commitments: Tuple[Point, ...],
        repair_participants: Optional[Tuple[int, ...]] = None,
    ):
        """
        Retrieves the repair share commitment for the given participant index.

        Parameters:
        participant_index (int): The index of the participant.
        repair_share_commitments (Tuple[Point, ...]): The commitments of the
        participant who generated the repair share.
        repair_participants (Tuple[int, ...]): Indices of participants involved in the repair.

        Returns:
        The repair share commitment associated with the given participant index.

        Raises:
        IndexError: If the participant_index does not match the initial set.
        """
        if repair_participants is None:
            if not self.repair_participants:
                raise ValueError("Repair participants must be initialized or provided.")
            repair_participants = self.repair_participants
        if participant_index not in repair_participants:
            raise IndexError("Participant index does not match the initial set.")

        mapped_index = repair_participants.index(participant_index)
        return repair_share_commitments[mapped_index]

    def verify_aggregate_repair_share(
        self,
        aggregate_repair_share: int,
        repair_share_commitments: Tuple[Tuple[Point, ...]],
        aggregator_index: int,
        repair_participants: Tuple[int, ...],
        group_commitments: Tuple[Point, ...],
    ) -> bool:
        """
        Verify the aggregate repair share against the provided commitments.

        Parameters:
        aggregate_repair_share (int): The aggregate repair share to verify.
        repair_share_commitments (Tuple[Tuple[Point, ...]]): The commitments of
        the participants who generated the repair shares that were aggregated.
        aggregator_index (int): The index of the participant who generated the
        aggregate repair share being verified.
        repair_participants (Tuple[int, ...]): Indices of participants involved in the repair.
        group_commitments (Tuple[Point, ...]): The group commitments for the signing shares.

        Returns:
        bool: True if the aggregate repair share is valid according to the
        commitments, False otherwise.

        Raises:
        ValueError: If the number of repair share commitments does not match the threshold.
        """
        if len(repair_share_commitments) != self.threshold:
            raise ValueError(
                "The number of repair share commitments must match the threshold."
            )
        for dealer_index, commitments in zip(
            repair_participants, repair_share_commitments
        ):
            lagrange_coefficient = self._lagrange_coefficient(
                repair_participants, self.index, dealer_index
            )
            dealer_public_share = self.derive_public_verification_share(
                group_commitments, dealer_index, self.threshold
            )
            if lagrange_coefficient * dealer_public_share != sum(commitments, Point()):
                return False

        aggregate_repair_share_commitment = sum(
            tuple(
                self.get_repair_share_commitment(
                    aggregator_index, commitments, repair_participants
                )
                for commitments in repair_share_commitments
            ),
            Point(),
        )

        return aggregate_repair_share * G == aggregate_repair_share_commitment

    def verify_repair_share(
        self,
        repair_share: int,
        repair_share_commitments: Tuple[Point, ...],
        repair_index: int,
        dealer_index: int,
    ) -> bool:
        """
        Verify the repair share against the provided commitments.

        Parameters:
        repair_share (int): The repair share to verify.
        repair_share_commitments (Tuple[Point, ...]): The commitments of the
        participant who generated the repair share.
        repair_index (int): The index of the participant with the lost share.
        dealer_index (int): The index of the participant who generated the repair shares.

        Returns:
        bool: True if the repair share is valid according to the commitments, False otherwise.

        Raises:
        ValueError: If the number of repair share commitments does not match
        the threshold, or the group commitment is uninitialized.
        """
        if not self.group_commitments:
            raise ValueError("Group commitments must be initialized.")
        if not self.repair_participants:
            raise ValueError("Repair participants must be initialized.")
        if repair_share * G != self.get_repair_share_commitment(
            self.index, repair_share_commitments
        ):
            return False
        if len(repair_share_commitments) != self.threshold:
            raise ValueError(
                "The number of repair share commitments must match the threshold."
            )

        lagrange_coefficient = self._lagrange_coefficient(
            self.repair_participants, repair_index, dealer_index
        )
        dealer_public_share = self.derive_public_verification_share(
            self.group_commitments, dealer_index, self.threshold
        )
        return lagrange_coefficient * dealer_public_share == sum(
            repair_share_commitments, Point()
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
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")

        y = 0
        for coefficient in reversed(self.coefficients):
            y = (y * x + coefficient) % Q
        return y

    def _lagrange_coefficient(
        self,
        participant_indexes: Tuple[int, ...],
        x: int = 0,
        participant_index: Optional[int] = None,
    ) -> int:
        """
        Calculate the Lagrange coefficient for this participant relative to other participants.

        Parameters:
        participant_indexes (Tuple[int, ...]): A tuple of indices of other
        participants involved in the calculation.
        x (int, optional): The point at which the polynomial is evaluated.
        Defaults to 0, representing the polynomial's constant term.
        participant_index (int, optional): The index of the participant for
        which the coefficient is calculated.

        Returns:
        int: The Lagrange coefficient used in polynomial reconstruction or signature generation.

        Raises:
        ValueError: If duplicate indices are found.
        """

        if len(participant_indexes) != len(set(participant_indexes)):
            raise ValueError("Participant indexes must be unique.")

        if participant_index is None:
            participant_index = self.index

        # λ_i(x) = ∏ (x - p_j)/(p_i - p_j), 1 ≤ j ≤ α, j ≠ i
        numerator = 1
        denominator = 1
        for index in participant_indexes:
            if index == participant_index:
                continue
            numerator = numerator * (x - index)
            denominator = denominator * (participant_index - index)
        return (numerator * pow(denominator, Q - 2, Q)) % Q

    def verify_share(
        self, share: int, coefficient_commitments: Tuple[Point, ...], threshold: int
    ) -> bool:
        """
        Verify that a given share matches the expected value derived from coefficient commitments.

        Parameters:
        share (int): The share to verify.
        coefficient_commitments (Tuple[Point, ...]): The commitments of the coefficients.
        threshold (int): The minimum number of participants required to generate a valid signature.

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
        expected_share = self.derive_public_verification_share(
            coefficient_commitments, self.index, threshold
        )

        # g^f_l(i) ≟ ∏ 𝜙_l_k^i^k mod q, 0 ≤ k ≤ t - 1
        return share * G == expected_share

    def aggregate_shares(self, other_shares: Tuple[int, ...]) -> None:
        """
        Aggregate the shares from all participants to compute the participant's aggregate share.

        Parameters:
        other_shares (Tuple[int, ...]): A tuple of integer shares from other participants.

        Raises:
        ValueError: If the participant's shares have not been initialized, the
        participant's index is out of range, or the number of other shares does
        not match the number of participants minus one.
        TypeError: If any of the provided shares are not integers.
        """
        if not self.shares:
            raise ValueError("Participant's shares have not been initialized.")
        if not 0 <= self.index - 1 < len(self.shares):
            raise ValueError("Participant index is out of range.")
        if len(other_shares) != self.participants - 1:
            raise ValueError(
                f"""
                Expected exactly {self.participants - 1} other shares, received
                {len(other_shares)}.
                """
            )

        # s_i = ∑ f_l(i), 1 ≤ l ≤ n
        aggregate_share = self.shares[self.index - 1]
        if not isinstance(aggregate_share, int):
            raise TypeError("All shares must be integers.")
        for other_share in other_shares:
            if not isinstance(other_share, int):
                raise TypeError("All shares must be integers.")
            aggregate_share = (aggregate_share + other_share) % Q

        if self.aggregate_share is not None:
            self.aggregate_share = (self.aggregate_share + aggregate_share) % Q
        else:
            self.aggregate_share = aggregate_share

    def aggregate_repair_shares(self, other_shares: Tuple[int, ...]) -> None:
        """
        Aggregate the repair shares from participants to compute the
        participant's aggregate repair share.

        Parameters:
        other_shares (Tuple[int, ...]): A tuple of integer repair shares from other participants.

        Raises:
        ValueError: If the participant's shares have not been initialized or
        the number of other repair shares does not match the threshold minus
        one.
        TypeError: If any of the provided shares are not integers.
        """
        if not self.repair_shares:
            raise ValueError("Participant's repair shares have not been initialized.")
        if len(other_shares) != self.threshold - 1:
            raise ValueError(
                f"""
                Expected exactly {self.threshold - 1} other shares, received
                {len(other_shares)}.
                """
            )

        aggregate_repair_share = self.get_repair_share(self.index)
        if not isinstance(aggregate_repair_share, int):
            raise TypeError("All shares must be integers.")
        for other_share in other_shares:
            if not isinstance(other_share, int):
                raise TypeError("All shares must be integers.")
            aggregate_repair_share = (aggregate_repair_share + other_share) % Q

        self.aggregate_repair_share = aggregate_repair_share

    def repair_share(self, aggregate_repair_shares: Tuple[int, ...]) -> None:
        """
        Repair or reconstruct the participant's aggregate share from provided repair shares.

        Parameters:
        aggregate_repair_shares (Tuple[int, ...]): A tuple of integer shares
        used for the reconstruction.

        Raises:
        ValueError: If the participant's share has not been lost or the number
        of repair shares does not match the threshold.
        TypeError: If any of the provided shares are not integers.
        """
        if self.aggregate_share is not None:
            raise ValueError("Participant's share has not been lost")
        if len(aggregate_repair_shares) != self.threshold:
            raise ValueError(
                f"""
                Expected exactly {self.threshold} aggregate repair shares,
                received {len(aggregate_repair_shares)}.
                """
            )

        for aggregate_repair_share in aggregate_repair_shares:
            if not isinstance(aggregate_repair_share, int):
                raise TypeError("All shares must be integers.")

        self.aggregate_share = sum(aggregate_repair_shares) % Q

    def decrement_threshold(
        self, revealed_share: int, revealed_share_index: int
    ) -> None:
        """
        Decrement the threshold by one and adjust the participant's share accordingly.

        Parameters:
        revealed_share (int): The share that was publicly revealed.
        revealed_share_index (int): The index of the share that was publicly revealed.

        Raises:
        ValueError: If the participant's share has not been initialized.
        """
        if self.aggregate_share is None:
            raise ValueError("Participant's share has not been initialized.")
        if self.group_commitments is None:
            raise ValueError("Group commitments have not been initialized.")

        # f'(i) = f(j) - j((f(i) - f(j))/(i - j))
        numerator = self.aggregate_share - revealed_share
        denominator = self.index - revealed_share_index
        quotient = (numerator * pow(denominator, Q - 2, Q)) % Q
        self.aggregate_share = (revealed_share - (revealed_share_index * quotient)) % Q

        self.threshold -= 1
        public_verification_shares = []
        indexes = []
        F_j = revealed_share * G
        for index in range(1, self.threshold + 1):
            F_i = self.derive_public_verification_share(
                self.group_commitments, index, self.threshold + 1
            )
            inverse_i_j = pow((index - revealed_share_index), Q - 2, Q) % Q
            Fp_i = F_j - (revealed_share_index * inverse_i_j) * (F_i - F_j)
            public_verification_shares.append(Fp_i)
            indexes.append(index)
        group_commitments = self.derive_coefficient_commitments(
            tuple(public_verification_shares), tuple(indexes)
        )
        self.group_commitments = group_commitments

    def increase_threshold(self, other_shares: Tuple[int, ...]) -> None:
        """
        Aggregate shares to increase the threshold.

        Parameters:
        other_shares (Tuple[int, ...]): A tuple of shares from other
        participants that are used to increase the threshold.

        Raises:
        ValueError: If the participant's own initial shares or the aggregate share have not been
        initialized.
        """
        if not self.shares:
            raise ValueError("Participant's shares have not been initialized.")
        if not self.aggregate_share:
            raise ValueError("Participant's aggregate share has not been initialized.")

        aggregate_share = (self.shares[self.index - 1] + sum(other_shares)) % Q
        self.aggregate_share += (aggregate_share * self.index) % Q

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

    def derive_public_verification_share(
        self, coefficient_commitments: Tuple[Point, ...], index: int, threshold: int
    ) -> Point:
        """
        Compute the public verification share of any participant from the
        coefficient commitments.

        Parameters:
        coefficient_commitments (Tuple[Point, ...]): A tuple of coefficients commitments.
        index (int): The index of the participant whose public verification share is derived.
        threshold (int): The minimum number of participants required to generate a valid signature.

        Returns:
        Point: The public verification share as a point on the elliptic curve.

        Raises:
        ValueError: If the number of coefficient commitments does not match the
        threshold.
        """
        if len(coefficient_commitments) != threshold:
            raise ValueError(
                "The number of coefficient commitments must match the threshold."
            )

        expected_y_commitment = Point()  # Point at infinity
        for k, commitment in enumerate(coefficient_commitments):
            expected_y_commitment += (index**k % Q) * commitment

        return expected_y_commitment

    def derive_public_key(self, other_secret_commitments: Tuple[Point, ...]) -> Point:
        """
        Derive the public key by summing up the secret commitments.

        Parameters:
        other_secret_commitments (Tuple[Point, ...]): A tuple of secret
        commitments from other participants.

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

    def derive_group_commitments(
        self, other_coefficient_commitments: Tuple[Tuple[Point, ...]]
    ) -> None:
        """
        Derives and updates the group commitments for the instance by combining
        existing coefficient commitments with those passed as an argument.

        This method performs an element-wise summation of point tuples from
        `self.coefficient_commitments` and `other_coefficient_commitments`. If
        `self.group_commitments` is already initialized, it updates it by
        further combining it with the newly derived group commitments;
        otherwise, it initializes `self.group_commitments` with these derived
        values.

        Parameters:
        other_coefficient_commitments (Tuple[Tuple[Point, ...]]): A tuple of
        tuples containing Point objects, representing the coefficient
        commitments from the other participants.

        Raises:
        ValueError: If `self.coefficient_commitments` is not initialized or is
        empty, indicating that there are no existing coefficient commitments to
        combine with.

        Returns:
        None: This method updates the group commitments in-place and does not return any value.
        """
        if not self.coefficient_commitments:
            raise ValueError(
                "Coefficient commitments have not been initialized or are empty."
            )

        group_commitments = tuple(
            sum(commitments, Point())
            for commitments in zip(
                *(other_coefficient_commitments + (self.coefficient_commitments,))
            )
        )

        if self.group_commitments is not None:
            self.group_commitments = tuple(
                sum(commitments, Point())
                for commitments in zip(self.group_commitments, group_commitments)
            )
        else:
            self.group_commitments = group_commitments

    def generate_nonce_pair(self) -> None:
        """
        Generate a nonce pairs and their elliptic curve commitments for
        cryptographic operations.
        """
        # (d_i_j, e_i_j) ⭠ $ ℤ*_q x ℤ*_q
        nonce_pair = (secrets.randbits(256) % Q, secrets.randbits(256) % Q)
        # (D_i_j, E_i_j) = (g^d_i_j, g^e_i_j)
        nonce_commitment_pair = (nonce_pair[0] * G, nonce_pair[1] * G)

        self.nonce_pair = nonce_pair
        self.nonce_commitment_pair = nonce_commitment_pair

    def sign(
        self,
        message: bytes,
        nonce_commitment_pairs: Tuple[Tuple[Point, Point], ...],
        participant_indexes: Tuple[int, ...],
        bip32_tweak: Optional[int] = None,
        taproot_tweak: Optional[int] = None,
    ) -> int:
        """
        Generate a signature contribution for this participant.

        Parameters:
        message (bytes): The message being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): Tuple of
        tuples of nonce commitments.
        participant_indexes (Tuple[int, ...]): Tuple of participant indexes involved in the signing.

        Returns:
        int: The signature share of this participant.

        Raises:
        ValueError: If required cryptographic elements are not properly initialized.
        """
        if self.nonce_pair is None:
            raise ValueError("Nonce pair has not been initialized.")
        if self.public_key is None:
            raise ValueError("Public key has not been initialized.")
        if self.public_key.x is None or self.public_key.y is None:
            raise ValueError("Public key is the point at infinity.")
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")

        # R
        group_commitment = Aggregator.group_commitment(
            message, nonce_commitment_pairs, participant_indexes
        )
        if group_commitment.x is None or group_commitment.y is None:
            raise ValueError("Group commitment is the point at infinity.")

        public_key = self.public_key
        parity = 0
        if bip32_tweak is not None and taproot_tweak is not None:
            public_key, parity = Aggregator.tweak_key(
                bip32_tweak, taproot_tweak, self.public_key
            )

        # c = H_2(R, Y, m)
        challenge_hash = Aggregator.challenge_hash(
            group_commitment, public_key, message
        )

        # d_i, e_i
        first_nonce, second_nonce = self.nonce_pair

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
        if public_key.y is None:
            raise ValueError("Public key is the point at infinity.")
        if public_key.y % 2 != parity:
            aggregate_share = Q - aggregate_share

        # z_i = d_i + (e_i * p_i) + λ_i * s_i * c
        return (
            first_nonce
            + (second_nonce * binding_value)
            + lagrange_coefficient * aggregate_share * challenge_hash
        ) % Q

    def derive_coefficient_commitments(
        self,
        public_verification_shares: Tuple[Point, ...],
        participant_indexes: Tuple[int, ...],
    ) -> Tuple[Point, ...]:
        """
        Derive polynomial coefficient commitments from public verification shares.

        This method computes the coefficient commitments for a polynomial given
        a set of public verification shares and the corresponding participant
        indexes. It uses a Vandermonde matrix approach to solve for the
        coefficients. The matrix is constructed based on the participant
        indexes, inverted, and then used to multiply with the matrix of public
        verification shares. The result is the coefficients expressed as
        points, representing the commitments.

        Parameters:
        public_verification_shares (Tuple[Point, ...]): A tuple of Point
        instances representing public verification shares for each participant.
        participant_indexes (Tuple[int, ...]): A tuple of integers representing
        the indexes of participants which are used to build the Vandermonde
        matrix.

        Returns:
        Tuple[Point, ...]: A tuple of Point instances representing the
        polynomial coefficients, which are the derived commitments from the
        provided public verification shares.

        Raises:
        ValueError: If the number of public verification shares does not match
        the number of participant indexes.
        """
        if len(public_verification_shares) != len(participant_indexes):
            raise ValueError(
                """
                The number of public verification shares must match the number
                of participant indexes.
                """
            )

        A = Matrix.create_vandermonde(participant_indexes)
        A_inv = A.inverse_matrix()
        Y = tuple((share,) for share in public_verification_shares)
        coefficients = A_inv.mult_point_matrix(Y)

        return tuple(coeff[0] for coeff in coefficients)

    def derive_shared_secret_share(
        self, public_key: Point, participant_indexes: Tuple[int, ...]
    ) -> Point:
        """
        Derives a shared secret share using a public key and participant
        indexes.

        This method calculates a shared secret share by applying a Lagrange
        coefficient to the aggregate share and then multiplying the result by
        the provided public key.

        The share secret shares derived from this method can be aggregated with
        Aggregator.derive_shared_secret.

        Parameters:
        public_key : Point
            The public key used in the derivation of the shared secret share.
        participant_indexes : Tuple[int, ...]
            A tuple containing the indexes of the participants involved in the
        secret sharing scheme.

        Returns:
        Point
            The derived shared secret share.

        Raises:
        ValueError
            If the aggregate share has not been initialized.
        """
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")

        lagrange_coefficient = self._lagrange_coefficient(participant_indexes)

        return (lagrange_coefficient * self.aggregate_share) * public_key
