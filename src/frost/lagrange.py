"""
Lagrange interpolation over the scalar field of secp256k1.

Lagrange interpolation reconstructs a polynomial from a set of evaluation points.
In Shamir's Secret Sharing, a degree-(t-1) polynomial f(x) encodes a secret as
its constant term f(0). Given t points (xᵢ, f(xᵢ)), the secret is recovered by
interpolating the polynomial and evaluating at x=0.

The Lagrange coefficient λᵢ(x) determines participant i's "weight" when
combining shares. The formula is:

    λᵢ(x) = ∏((x - xⱼ) / (xᵢ - xⱼ)) for j in participants, j ≠ i

When x=0 (the default), this simplifies to secret reconstruction. FROST signing
also uses these coefficients: each signer weights their signature share by their
Lagrange coefficient so the partial signatures combine correctly.

All arithmetic is in Z_Q (the scalar field), so division is modular inverse.
"""

from .constants import Q
from .scalar import Scalar


def lagrange_coefficient(
    participant_indexes: tuple[int, ...],
    participant_index: int,
    x: int = 0,
) -> Scalar:
    """Compute the Lagrange interpolation coefficient for a participant.

    This is the core building block of Shamir's Secret Sharing. The Lagrange
    coefficient λᵢ(x) determines participant i's "weight" when
    reconstructing a shared secret at evaluation point x.

        λᵢ(x) = ∏((x - xⱼ) / (xᵢ - xⱼ)) for j in participants, j ≠ i

    Used in:
    - Secret reconstruction (x=0 recovers the constant term = the secret)
    - FROST signing (participants weight their shares by λᵢ)
    - Share repair (repairing participants contribute weighted shares)

    Parameters:
        participant_indexes: Indexes of all participants in the interpolation set.
        participant_index: The index of the participant whose coefficient to compute.
        x: The evaluation point (default 0 for secret reconstruction).

    Returns:
        The Lagrange coefficient as a Scalar.

    Raises:
        ValueError: If participant indexes contain duplicates.
    """
    if len(participant_indexes) != len(set(participant_indexes)):
        raise ValueError("Participant indexes must be unique.")

    # λᵢ(x) = ∏((x - xⱼ) / (xᵢ - xⱼ)), j ≠ i
    numerator = 1
    denominator = 1
    for index in participant_indexes:
        if index == participant_index:
            continue
        numerator = numerator * (x - index)
        denominator = denominator * (participant_index - index)

    # Modular inverse via Fermat's little theorem: a^(Q-2) = a^(-1) (mod Q)
    return Scalar((numerator * pow(denominator, Q - 2, Q)) % Q)
