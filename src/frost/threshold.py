"""
Threshold change operations for FROST.

These are advanced operations that modify the threshold of an existing FROST
group without changing the shared secret or requiring a new DKG ceremony.

Threshold increase: Participants jointly generate new polynomial shares to
raise the minimum signers required. Each participant's share is adjusted by
combining new sub-shares. The group secret remains unchanged.

Threshold decrease: A participant publicly reveals their share, which allows
all other participants to "factor out" that share from their own, effectively
lowering the degree of the underlying polynomial. This is destructive to the
revealing participant's share.

Coefficient commitment derivation: Given public verification shares and their
indexes, recover the polynomial's coefficient commitments via Vandermonde
matrix inversion. Used after threshold changes to update group commitments.

References:
- Dynamic threshold schemes (Desmedt & Jajodia, 1997)
- FROST threshold modifications follow similar algebraic principles
"""

from .keygen import derive_public_verification_share
from .matrix import Matrix
from .point import G, Point
from .scalar import Scalar


def increase_threshold(
    aggregate_share: Scalar,
    own_new_shares: tuple[Scalar, ...],
    other_new_shares: tuple[Scalar, ...],
    index: int,
) -> Scalar:
    """Adjust a participant's share for an increased threshold.

    When the threshold is increased from t to t', each participant generates a
    new polynomial of degree (t' - t - 1) and distributes evaluations. The
    participant then adjusts their aggregate share by adding the sum of all
    new evaluations (own + received), weighted by their index.

    The index weighting ensures that the new shares combine correctly with the
    existing polynomial to form a higher-degree polynomial with the same
    constant term (the group secret remains unchanged).

    Parameters:
        aggregate_share: The participant's current aggregate share s_i.
        own_new_shares: This participant's evaluation of their own new polynomial
            at their own index: f_i(i).
        other_new_shares: Evaluations of other participants' new polynomials
            at this participant's index: f_j(i) for j != i.
        index: This participant's index.

    Returns:
        The updated aggregate share.
    """
    # Sum own evaluation at own index with all received evaluations
    new_share_sum = Scalar(0)
    for s in own_new_shares:
        new_share_sum = new_share_sum + s
    for s in other_new_shares:
        new_share_sum = new_share_sum + s

    # Weight by participant index and add to existing share
    adjustment = new_share_sum * Scalar(index)
    return aggregate_share + adjustment


def decrement_threshold(
    aggregate_share: Scalar,
    revealed_share: Scalar,
    revealed_index: int,
    own_index: int,
    group_commitments: tuple[Point, ...],
    threshold: int,
) -> tuple[Scalar, tuple[Point, ...]]:
    """Reduce the threshold by one using a publicly revealed share.

    When a participant reveals their share f(j), all remaining participants
    can compute their new shares on a degree-(t-2) polynomial that encodes
    the same secret. The transformation is:

        f'(i) = f(j) - j * (f(i) - f(j)) / (i - j)

    This is a polynomial division: we are "factoring out" the revealed
    participant's contribution. The group commitments are similarly updated
    by computing new public verification shares on the lower-degree polynomial
    and recovering the coefficients via Vandermonde inversion.

    Warning: this is destructive. The revealing participant permanently loses
    their share and can no longer participate.

    Parameters:
        aggregate_share: This participant's current aggregate share.
        revealed_share: The publicly revealed share f(j).
        revealed_index: The index j of the participant who revealed.
        own_index: This participant's index i.
        group_commitments: The current group coefficient commitments.
        threshold: The current threshold t (will become t-1).

    Returns:
        (new_aggregate_share, new_group_commitments) for the reduced threshold.
    """
    # f'(i) = f(j) - j * ((f(i) - f(j)) / (i - j))
    numerator = aggregate_share - revealed_share
    denominator = Scalar(own_index - revealed_index)
    quotient = numerator * denominator.inv()
    new_share = revealed_share - Scalar(revealed_index) * quotient

    # Compute new public verification shares on the lower-degree polynomial
    new_threshold = threshold - 1
    F_j = int(revealed_share) * G
    public_verification_shares = []
    indexes = []
    for idx in range(1, new_threshold + 1):
        F_i = derive_public_verification_share(group_commitments, idx)
        inv_diff = Scalar(idx - revealed_index).inv()
        Fp_i = F_j - (int(Scalar(revealed_index) * inv_diff) * (F_i - F_j))
        public_verification_shares.append(Fp_i)
        indexes.append(idx)

    new_group_commitments = derive_coefficient_commitments(
        tuple(public_verification_shares), tuple(indexes)
    )

    return (new_share, new_group_commitments)


def derive_coefficient_commitments(
    public_verification_shares: tuple[Point, ...],
    participant_indexes: tuple[int, ...],
) -> tuple[Point, ...]:
    """Recover polynomial coefficient commitments from verification shares.

    Uses Vandermonde matrix inversion: given points (index, Y_i) on the
    commitment polynomial, solve for the coefficients.

    The Vandermonde matrix V has entries V[i][k] = indexᵢ^k. Given the
    verification shares Y = (Y₁, …, Yₙ), the coefficient commitments
    C = (C₀, …, C_{n-1}) satisfy V·C = Y. So C = V⁻¹·Y.

    This is used after threshold changes to recover the new group commitments
    from the updated public verification shares.

    Parameters:
        public_verification_shares: The verification shares Yᵢ = sᵢ·G.
        participant_indexes: The corresponding participant indexes.

    Returns:
        The polynomial coefficient commitments (C₀, C₁, …, C_{t-1}).

    Raises:
        ValueError: If the number of shares doesn't match the number of indexes.
    """
    if len(public_verification_shares) != len(participant_indexes):
        raise ValueError(
            "The number of public verification shares must match the number "
            "of participant indexes."
        )

    A = Matrix.create_vandermonde(participant_indexes)
    A_inv = A.inverse_matrix()
    Y = tuple((share,) for share in public_verification_shares)
    coefficients = A_inv.mult_point_matrix(Y)

    return tuple(coeff[0] for coeff in coefficients)
