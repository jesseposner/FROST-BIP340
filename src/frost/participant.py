"""FROST participant: state container and protocol orchestrator."""

from . import keygen, repair, signing, threshold
from .lagrange import lagrange_coefficient
from .point import Point
from .polynomial import (
    generate_polynomial,
    generate_refresh_polynomial,
    generate_threshold_increase_polynomial,
)
from .scalar import Scalar


class Participant:
    """A FROST participant: state container and protocol orchestrator.

    This class holds a participant's state across all protocol phases and
    delegates to protocol-phase modules for cryptographic operations.

    To understand FROST, read the individual modules:
    - keygen.py:     Distributed Key Generation (DKG)
    - signing.py:    FROST threshold signing
    - repair.py:     Share repair and enrollment
    - threshold.py:  Threshold increase and decrease

    This class shows how the phases compose: keygen produces shares and
    keys, signing consumes them, repair regenerates lost shares.
    """

    CONTEXT = b"FROST-BIP340"

    def __init__(self, index: int, threshold: int, participants: int):
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

    def _scalar_coeffs(self) -> tuple[Scalar, ...]:
        return tuple(Scalar(c) for c in self.coefficients)

    def _init_commitments(self) -> None:
        self.coefficient_commitments = keygen.compute_coefficient_commitments(
            self._scalar_coeffs()
        )

    def _init_proof(self) -> None:
        r = keygen.compute_proof_of_knowledge(
            Scalar(self.coefficients[0]), self.index, self.CONTEXT
        )
        self.proof_of_knowledge = (r[0], int(r[1]))

    def init_keygen(self) -> None:
        """Generate polynomial, proof of knowledge, and coefficient commitments."""
        self.coefficients = tuple(int(c) for c in generate_polynomial(self.threshold))
        self._init_proof()
        self._init_commitments()

    def init_refresh(self) -> None:
        """Generate refresh polynomial (constant term = 0) and commitments."""
        self.coefficients = tuple(int(c) for c in generate_refresh_polynomial(self.threshold))
        self._init_commitments()

    def init_threshold_increase(self, new_threshold: int) -> None:
        """Generate threshold-increase polynomial and commitments."""
        if not isinstance(new_threshold, int):
            raise ValueError("New threshold must be an integer.")
        if new_threshold <= self.threshold:
            raise ValueError("New threshold must be greater than the current threshold.")
        self.coefficients = tuple(
            int(c) for c in generate_threshold_increase_polynomial(new_threshold)
        )
        self._init_proof()
        self._init_commitments()
        self.threshold = new_threshold

    def verify_proof_of_knowledge(
        self, proof: tuple[Point, int], secret_commitment: Point, index: int
    ) -> bool:
        """Verify a proof of knowledge. See keygen.verify_proof_of_knowledge."""
        return keygen.verify_proof_of_knowledge(
            (proof[0], Scalar(proof[1])), secret_commitment, index, self.CONTEXT
        )

    def generate_shares(self):
        """Generate shares for each participant. See keygen.generate_shares."""
        if not self.coefficients:
            raise ValueError("Polynomial coefficients must be initialized.")
        self.shares = tuple(
            int(s) for s in keygen.generate_shares(self._scalar_coeffs(), self.participants)
        )

    def verify_share(self, share: int, coefficient_commitments: tuple[Point, ...], threshold: int):
        """Verify a share against coefficient commitments. See keygen.verify_share."""
        if len(coefficient_commitments) != threshold:
            raise ValueError("The number of coefficient commitments must match the threshold.")
        return keygen.verify_share(Scalar(share), self.index, coefficient_commitments)

    def aggregate_shares(self, other_shares: tuple[int, ...]) -> None:
        """Aggregate shares to compute this participant's aggregate share."""
        if not self.shares:
            raise ValueError("Participant's shares have not been initialized.")
        if len(other_shares) != self.participants - 1:
            raise ValueError(
                f"Expected {self.participants - 1} other shares, got {len(other_shares)}."
            )
        result = keygen.aggregate_shares(
            Scalar(self.shares[self.index - 1]), tuple(Scalar(s) for s in other_shares)
        )
        if self.aggregate_share is not None:
            self.aggregate_share = int(Scalar(self.aggregate_share) + result)
        else:
            self.aggregate_share = int(result)

    def derive_public_key(self, other_secret_commitments: tuple[Point, ...]) -> Point:
        """Derive the group public key. See keygen.derive_public_key."""
        if not self.coefficient_commitments:
            raise ValueError("Coefficient commitments have not been initialized.")
        self.public_key = keygen.derive_public_key(
            self.coefficient_commitments[0], other_secret_commitments
        )
        return self.public_key

    def derive_group_commitments(self, other_cc: tuple[tuple[Point, ...]]) -> None:
        """Derive group commitments. See keygen.derive_group_commitments."""
        if not self.coefficient_commitments:
            raise ValueError("Coefficient commitments have not been initialized.")
        self.group_commitments = keygen.derive_group_commitments(
            self.coefficient_commitments, other_cc, existing=self.group_commitments
        )

    def public_verification_share(self) -> Point:
        """Compute Y_i = s_i * G. See keygen.public_verification_share."""
        if self.aggregate_share is None:
            raise AttributeError("Aggregate share has not been initialized.")
        return keygen.public_verification_share(Scalar(self.aggregate_share))

    def derive_public_verification_share(
        self, coefficient_commitments: tuple[Point, ...], index: int, threshold: int
    ) -> Point:
        """Derive Y_i from commitments. See keygen.derive_public_verification_share."""
        if len(coefficient_commitments) != threshold:
            raise ValueError("The number of coefficient commitments must match the threshold.")
        return keygen.derive_public_verification_share(coefficient_commitments, index)

    def generate_nonce_pair(self) -> None:
        """Generate a fresh nonce pair for signing. See signing.generate_nonce_pair."""
        scalar_pair, commitment_pair = signing.generate_nonce_pair()
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
        """Compute this participant's signature share. See signing.sign."""
        if self.nonce_pair is None:
            raise ValueError("Nonce pair has not been initialized.")
        if self.public_key is None:
            raise ValueError("Public key has not been initialized.")
        if self.public_key.x is None or self.public_key.y is None:
            raise ValueError("Public key is the point at infinity.")
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")
        return int(
            signing.sign(
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
        )

    def generate_repair_shares(self, repair_participants: tuple[int, ...], index: int) -> None:
        """Generate repair shares. See repair.generate_repair_shares."""
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")
        shares, commitments, sorted_p = repair.generate_repair_shares(
            Scalar(self.aggregate_share), self.threshold, repair_participants, index, self.index
        )
        self.repair_shares = tuple(int(s) for s in shares)
        self.repair_share_commitments = commitments
        self.repair_participants = sorted_p

    def get_repair_share(self, participant_index):
        """Get repair share for a participant. See repair.get_repair_share."""
        if self.repair_participants is None or self.repair_shares is None:
            raise ValueError("Repair shares have not been initialized.")
        return int(
            repair.get_repair_share(
                tuple(Scalar(s) for s in self.repair_shares),
                self.repair_participants,
                participant_index,
            )
        )

    def get_repair_share_commitment(
        self,
        participant_index,
        repair_share_commitments: tuple[Point, ...],
        repair_participants: tuple[int, ...] | None = None,
    ):
        """Get repair share commitment. See repair.get_repair_share_commitment."""
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
        """Verify aggregate repair share. See repair.verify_aggregate_repair_share."""
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
        """Verify a repair share. See repair.verify_repair_share."""
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

    def aggregate_repair_shares(self, other_shares: tuple[int, ...]) -> None:
        """Aggregate repair shares. See repair.aggregate_repair_shares."""
        if not self.repair_shares:
            raise ValueError("Repair shares have not been initialized.")
        if len(other_shares) != self.threshold - 1:
            raise ValueError(
                f"Expected {self.threshold - 1} other shares, got {len(other_shares)}."
            )
        own_share = self.get_repair_share(self.index)
        self.aggregate_repair_share = int(
            repair.aggregate_repair_shares(
                Scalar(own_share), tuple(Scalar(s) for s in other_shares)
            )
        )

    def repair_share(self, aggregate_repair_shares: tuple[int, ...]) -> None:
        """Reconstruct this participant's share from repair shares."""
        if self.aggregate_share is not None:
            raise ValueError("Participant's share has not been lost")
        if len(aggregate_repair_shares) != self.threshold:
            raise ValueError(
                f"Expected {self.threshold} repair shares, got {len(aggregate_repair_shares)}."
            )
        self.aggregate_share = int(
            repair.reconstruct_share(tuple(Scalar(s) for s in aggregate_repair_shares))
        )

    def decrement_threshold(self, revealed_share: int, revealed_share_index: int) -> None:
        """Decrement threshold by one. See threshold.decrement_threshold."""
        if self.aggregate_share is None:
            raise ValueError("Participant's share has not been initialized.")
        if self.group_commitments is None:
            raise ValueError("Group commitments have not been initialized.")
        new_share, new_gc = threshold.decrement_threshold(
            Scalar(self.aggregate_share),
            Scalar(revealed_share),
            revealed_share_index,
            self.index,
            self.group_commitments,
            self.threshold,
        )
        self.aggregate_share = int(new_share)
        self.threshold -= 1
        self.group_commitments = new_gc

    def increase_threshold(self, other_shares: tuple[int, ...]) -> None:
        """Aggregate shares to increase the threshold. See threshold.increase_threshold."""
        if not self.shares:
            raise ValueError("Participant's shares have not been initialized.")
        if not self.aggregate_share:
            raise ValueError("Participant's aggregate share has not been initialized.")
        self.aggregate_share = int(
            threshold.increase_threshold(
                Scalar(self.aggregate_share),
                (Scalar(self.shares[self.index - 1]),),
                tuple(Scalar(s) for s in other_shares),
                self.index,
            )
        )

    def derive_coefficient_commitments(
        self, public_verification_shares: tuple[Point, ...], participant_indexes: tuple[int, ...]
    ) -> tuple[Point, ...]:
        """Derive coefficient commitments. See threshold.derive_coefficient_commitments."""
        return threshold.derive_coefficient_commitments(
            public_verification_shares, participant_indexes
        )

    def derive_shared_secret_share(
        self, public_key: Point, participant_indexes: tuple[int, ...]
    ) -> Point:
        """Derive a shared secret share for ECDH-style protocols."""
        if self.aggregate_share is None:
            raise ValueError("Aggregate share has not been initialized.")
        lam = int(lagrange_coefficient(participant_indexes, self.index))
        return (lam * self.aggregate_share) * public_key
