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

from . import keygen, repair, signing, threshold
from .lagrange import lagrange_coefficient as _lagrange_coeff
from .point import Point
from .polynomial import (
    evaluate_polynomial,
    generate_polynomial,
    generate_refresh_polynomial,
    generate_threshold_increase_polynomial,
)
from .scalar import Scalar


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
            raise ValueError("All arguments (index, threshold, participants) must be integers.")

        self.index = index
        self.threshold = threshold
        self.participants = participants
        self.coefficients: tuple[int, ...] | None = None
        self.coefficient_commitments: tuple[Point, ...] | None = None
        self.proof_of_knowledge: tuple[Point, int] | None = None
        self.shares: tuple[int, ...] | None = None
        self.aggregate_share: int | None = None
        self.nonce_pair: tuple[int, int] | None = None
        self.nonce_commitment_pair: tuple[Point, Point] | None = None
        self.public_key: Point | None = None
        self.repair_shares: tuple[int | None, ...] | None = None
        self.aggregate_repair_share: int | None = None
        self.repair_share_commitments: tuple[Point | None, ...] | None = None
        self.group_commitments: tuple[Point, ...] | None = None
        self.repair_participants: tuple[int, ...] | None = None

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
        Initialize proactive secret sharing refresh for a participant by generating
        a new polynomial with random coefficients and computing new coefficient
        commitments.
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
            raise ValueError("New threshold must be greater than the current threshold.")

        self._generate_threshold_increase_polynomial(new_threshold)
        self._compute_proof_of_knowledge()
        self._compute_coefficient_commitments()

        self.threshold = new_threshold

    def _generate_polynomial(self) -> None:
        """Generate random polynomial coefficients."""
        self.coefficients = tuple(int(c) for c in generate_polynomial(self.threshold))

    def _generate_refresh_polynomial(self) -> None:
        """
        Generate a polynomial with random coefficients for proactive secret
        sharing refresh, where the first coefficient is set to 0 to ensure the
        refresh does not change the shared secret.
        """
        self.coefficients = tuple(int(c) for c in generate_refresh_polynomial(self.threshold))

    def _generate_threshold_increase_polynomial(self, new_threshold: int) -> None:
        """
        Generate a polynomial with random coefficients for increasing the
        threshold, with a degree equal to the threshold minus two.

        Parameters:
        new_threshold (int): The new threshold value which must be an integer greater than the
        current threshold.
        """
        self.coefficients = tuple(
            int(c) for c in generate_threshold_increase_polynomial(new_threshold)
        )

    def _compute_proof_of_knowledge(self) -> None:
        """
        Compute the participant's proof of knowledge for the first coefficient,
        """
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")

        result = keygen.compute_proof_of_knowledge(
            Scalar(self.coefficients[0]), self.index, self.CONTEXT
        )
        # Store as (Point, int) for backward compatibility
        self.proof_of_knowledge = (result[0], int(result[1]))

    def _compute_coefficient_commitments(self) -> None:
        """
        Compute commitments to each coefficient for verification purposes,
        """
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")

        self.coefficient_commitments = keygen.compute_coefficient_commitments(
            tuple(Scalar(c) for c in self.coefficients)
        )

    def verify_proof_of_knowledge(
        self, proof: tuple[Point, int], secret_commitment: Point, index: int
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

        nonce_commitment, s = proof
        if not isinstance(nonce_commitment, Point) or not isinstance(s, int):
            raise ValueError("Proof must contain a Point and an integer.")

        # Convert int proof component to Scalar for the module function
        scalar_proof = (nonce_commitment, Scalar(s))
        return keygen.verify_proof_of_knowledge(
            scalar_proof, secret_commitment, index, self.CONTEXT
        )

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

        scalar_shares = keygen.generate_shares(
            tuple(Scalar(c) for c in self.coefficients), self.participants
        )
        self.shares = tuple(int(s) for s in scalar_shares)

    def generate_repair_shares(self, repair_participants: tuple[int, ...], index: int) -> None:
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

        shares, commitments, sorted_participants = repair.generate_repair_shares(
            Scalar(self.aggregate_share),
            self.threshold,
            repair_participants,
            index,
            self.index,
        )
        self.repair_shares = tuple(int(s) for s in shares)
        self.repair_share_commitments = commitments
        self.repair_participants = sorted_participants

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
        if self.repair_participants is None or self.repair_shares is None:
            raise ValueError("Repair participants or shares have not been initialized.")

        result = repair.get_repair_share(
            tuple(Scalar(s) for s in self.repair_shares),
            self.repair_participants,
            participant_index,
        )
        return int(result)

    def get_repair_share_commitment(
        self,
        participant_index,
        repair_share_commitments: tuple[Point, ...],
        repair_participants: tuple[int, ...] | None = None,
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

        return repair.get_repair_share_commitment(
            repair_share_commitments, repair_participants, participant_index
        )

    def verify_aggregate_repair_share(
        self,
        aggregate_repair_share: int,
        repair_share_commitments: tuple[tuple[Point, ...]],
        aggregator_index: int,
        repair_participants: tuple[int, ...],
        group_commitments: tuple[Point, ...],
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
        return repair.verify_aggregate_repair_share(
            Scalar(aggregate_repair_share),
            repair_share_commitments,
            aggregator_index,
            self.index,
            self.threshold,
            repair_participants,
            group_commitments,
        )

    def verify_repair_share(
        self,
        repair_share: int,
        repair_share_commitments: tuple[Point, ...],
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
        if len(repair_share_commitments) != self.threshold:
            raise ValueError("The number of repair share commitments must match the threshold.")

        return repair.verify_repair_share(
            Scalar(repair_share),
            repair_share_commitments,
            self.index,
            self.repair_participants,
            repair_index,
            dealer_index,
            self.group_commitments,
        )

    def _evaluate_polynomial(self, x: int) -> int:
        """
        Evaluate the polynomial at a given point x using Horner's method.

        Delegates to the standalone evaluate_polynomial function and converts
        the result back to int for backward compatibility with existing callers.

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
        scalar_coeffs = tuple(Scalar(c) for c in self.coefficients)
        return int(evaluate_polynomial(scalar_coeffs, x))

    def _lagrange_coefficient(
        self,
        participant_indexes: tuple[int, ...],
        x: int = 0,
        participant_index: int | None = None,
    ) -> int:
        """
        Calculate the Lagrange coefficient for this participant relative to other participants.

        Delegates to the standalone lagrange_coefficient function and converts
        the result back to int for backward compatibility with existing callers.

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
        if participant_index is None:
            participant_index = self.index
        return int(_lagrange_coeff(participant_indexes, participant_index, x))

    def verify_share(
        self, share: int, coefficient_commitments: tuple[Point, ...], threshold: int
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
            raise ValueError("The number of coefficient commitments must match the threshold.")

        return keygen.verify_share(Scalar(share), self.index, coefficient_commitments)

    def aggregate_shares(self, other_shares: tuple[int, ...]) -> None:
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

        own_share = self.shares[self.index - 1]
        if not isinstance(own_share, int):
            raise TypeError("All shares must be integers.")
        for other_share in other_shares:
            if not isinstance(other_share, int):
                raise TypeError("All shares must be integers.")

        result = keygen.aggregate_shares(Scalar(own_share), tuple(Scalar(s) for s in other_shares))

        if self.aggregate_share is not None:
            self.aggregate_share = int(Scalar(self.aggregate_share) + result)
        else:
            self.aggregate_share = int(result)

    def aggregate_repair_shares(self, other_shares: tuple[int, ...]) -> None:
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

        own_share = self.get_repair_share(self.index)
        if not isinstance(own_share, int):
            raise TypeError("All shares must be integers.")
        for other_share in other_shares:
            if not isinstance(other_share, int):
                raise TypeError("All shares must be integers.")

        result = repair.aggregate_repair_shares(
            Scalar(own_share), tuple(Scalar(s) for s in other_shares)
        )
        self.aggregate_repair_share = int(result)

    def repair_share(self, aggregate_repair_shares: tuple[int, ...]) -> None:
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

        for share in aggregate_repair_shares:
            if not isinstance(share, int):
                raise TypeError("All shares must be integers.")

        result = repair.reconstruct_share(tuple(Scalar(s) for s in aggregate_repair_shares))
        self.aggregate_share = int(result)

    def decrement_threshold(self, revealed_share: int, revealed_share_index: int) -> None:
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

        new_share, new_group_commitments = threshold.decrement_threshold(
            Scalar(self.aggregate_share),
            Scalar(revealed_share),
            revealed_share_index,
            self.index,
            self.group_commitments,
            self.threshold,
        )
        self.aggregate_share = int(new_share)
        self.threshold -= 1
        self.group_commitments = new_group_commitments

    def increase_threshold(self, other_shares: tuple[int, ...]) -> None:
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

        result = threshold.increase_threshold(
            Scalar(self.aggregate_share),
            (Scalar(self.shares[self.index - 1]),),
            tuple(Scalar(s) for s in other_shares),
            self.index,
        )
        self.aggregate_share = int(result)

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

        return keygen.public_verification_share(Scalar(self.aggregate_share))

    def derive_public_verification_share(
        self, coefficient_commitments: tuple[Point, ...], index: int, threshold: int
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
            raise ValueError("The number of coefficient commitments must match the threshold.")

        return keygen.derive_public_verification_share(coefficient_commitments, index)

    def derive_public_key(self, other_secret_commitments: tuple[Point, ...]) -> Point:
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
            raise ValueError("Coefficient commitments have not been initialized or are empty.")

        for other_secret_commitment in other_secret_commitments:
            if not isinstance(other_secret_commitment, Point):
                raise TypeError("All secret commitments must be Point instances.")

        self.public_key = keygen.derive_public_key(
            self.coefficient_commitments[0], other_secret_commitments
        )
        return self.public_key

    def derive_group_commitments(
        self, other_coefficient_commitments: tuple[tuple[Point, ...]]
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
            raise ValueError("Coefficient commitments have not been initialized or are empty.")

        self.group_commitments = keygen.derive_group_commitments(
            self.coefficient_commitments,
            other_coefficient_commitments,
            existing=self.group_commitments,
        )

    def generate_nonce_pair(self) -> None:
        """
        Generate a nonce pairs and their elliptic curve commitments for
        cryptographic operations.
        """
        scalar_pair, commitment_pair = signing.generate_nonce_pair()
        # Store nonce_pair as (int, int) for backward compatibility
        self.nonce_pair = (int(scalar_pair[0]), int(scalar_pair[1]))
        self.nonce_commitment_pair = commitment_pair

    def sign(
        self,
        message: bytes,
        nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
        participant_indexes: tuple[int, ...],
        bip32_tweak: int | None = None,
        taproot_tweak: int | None = None,
    ) -> int:
        """
        Generate a signature contribution for this participant.

        Parameters:
        message (bytes): The message being signed.
        nonce_commitment_pairs (Tuple[Tuple[Point, Point], ...]): Tuple of
        tuples of nonce commitments.
        participant_indexes (Tuple[int, ...]): Tuple of participant indexes involved
            in the signing.

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

        result = signing.sign(
            (Scalar(self.nonce_pair[0]), Scalar(self.nonce_pair[1])),
            Scalar(self.aggregate_share),
            self.public_key,
            self.index,
            message,
            nonce_commitment_pairs,
            participant_indexes,
            bip32_tweak,
            taproot_tweak,
        )
        return int(result)

    def derive_coefficient_commitments(
        self,
        public_verification_shares: tuple[Point, ...],
        participant_indexes: tuple[int, ...],
    ) -> tuple[Point, ...]:
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
        return threshold.derive_coefficient_commitments(
            public_verification_shares, participant_indexes
        )

    def derive_shared_secret_share(
        self, public_key: Point, participant_indexes: tuple[int, ...]
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
