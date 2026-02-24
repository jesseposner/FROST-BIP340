"""
Distributed Key Generation (DKG) for FROST threshold signatures.

DKG allows n participants to jointly generate a shared secret key without any
single participant knowing the full secret. Each participant:
1. Generates a random polynomial and commits to its coefficients
2. Proves knowledge of their secret (the constant term)
3. Evaluates their polynomial at each other participant's index to create shares
4. Distributes shares to other participants (verified against commitments)
5. Aggregates received shares into their private share of the group secret

The result: each participant holds a secret share sᵢ such that the shared
secret (the ∑ of all participants' constant terms) can be reconstructed
from any t shares via Lagrange interpolation, but fewer than t shares reveal
nothing.

References:
- Komlo, C. and Goldberg, I., "FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures," SAC 2020, LNCS 12804, Section 5.1.
- Pedersen, T. P., "A Threshold Cryptosystem without a Trusted Party,"
  EUROCRYPT '91, LNCS 547, pp. 522-526. (Original DKG protocol that
  FROST's key generation builds upon.)
- Feldman, P., "A Practical Scheme for Non-interactive Verifiable Secret
  Sharing," FOCS '87, pp. 427-438. (Share verification via coefficient
  commitments, used by verify_share.)
"""

from hashlib import sha256

from .constants import Q
from .point import G, Point
from .polynomial import evaluate_polynomial
from .scalar import Scalar


def compute_proof_of_knowledge(
    secret: Scalar,
    index: int,
    context: bytes = b"FROST-BIP340",
) -> tuple[Point, Scalar]:
    """Compute a Schnorr proof of knowledge of the secret coefficient a_i_0.

    This proves the participant knows the discrete log of their public
    commitment without revealing the secret itself. The proof is:
        σᵢ = (Rᵢ, μᵢ) where Rᵢ = k·G, μᵢ = k + a_i_0·cᵢ
    and cᵢ = H(i, context, a_i_0·G, Rᵢ).

    The proof structure is a standard Schnorr signature of knowledge:
    - The prover picks a random nonce k, publishes R = k·G
    - The challenge c binds the prover's identity (index), the context string,
      and both the secret commitment and nonce commitment
    - The response μ = k + secret·c proves knowledge of the secret

    Parameters:
        secret: The secret coefficient a_i_0 (constant term of the polynomial).
        index: The participant's unique index (1-indexed).
        context: Domain separation string for the challenge hash.

    Returns:
        (R, mu): The nonce commitment and the Schnorr response.
    """
    # k ← Z_Q (random nonce)
    nonce = Scalar.random()
    # Rᵢ = k·G (nonce commitment)
    nonce_commitment = int(nonce) * G
    # Build the challenge: cᵢ = H(i, context, a_i_0·G, Rᵢ)
    index_byte = index.to_bytes(1, "big")
    secret_commitment = int(secret) * G
    secret_commitment_bytes = secret_commitment.to_bytes_compressed()
    nonce_commitment_bytes = nonce_commitment.to_bytes_compressed()

    challenge_hash = sha256()
    challenge_hash.update(index_byte)
    challenge_hash.update(context)
    challenge_hash.update(secret_commitment_bytes)
    challenge_hash.update(nonce_commitment_bytes)
    challenge_hash_int = int.from_bytes(challenge_hash.digest(), "big")

    # μᵢ = k + a_i_0·cᵢ (Schnorr signature equation, mod Q)
    mu = nonce + secret * Scalar(challenge_hash_int)
    return (nonce_commitment, mu)


def verify_proof_of_knowledge(
    proof: tuple[Point, Scalar],
    secret_commitment: Point,
    index: int,
    context: bytes = b"FROST-BIP340",
) -> bool:
    """Verify a participant's proof of knowledge.

    Checks that the prover knows the discrete log of secret_commitment by
    verifying the Schnorr equation:
        Rᵢ == μᵢ·G - cᵢ·commitment

    This is algebraically equivalent to checking R = μ·G - c·φ, which
    holds only if the prover knew the secret when constructing μ.

    Parameters:
        proof: (R, mu) where R is the nonce commitment and mu is the response.
        secret_commitment: The public commitment to the secret (a_i_0 * G).
        index: The participant's unique index.
        context: Domain separation string (must match what the prover used).

    Returns:
        True if the proof is valid, False otherwise.
    """
    nonce_commitment, mu = proof
    # Reconstruct the challenge: cᵢ = H(i, context, a_i_0·G, Rᵢ)
    index_byte = index.to_bytes(1, "big")
    secret_commitment_bytes = secret_commitment.to_bytes_compressed()
    nonce_commitment_bytes = nonce_commitment.to_bytes_compressed()

    challenge_input = index_byte + context + secret_commitment_bytes + nonce_commitment_bytes
    challenge_hash_int = int.from_bytes(sha256(challenge_input).digest(), "big")

    # Verify: Rᵢ == μᵢ·G - cᵢ·commitment
    # Rewritten as: Rᵢ == μ·G + (Q - c)·commitment (negation in the scalar field)
    expected_nonce_commitment = (int(mu) * G) + ((Q - challenge_hash_int) * secret_commitment)
    return nonce_commitment == expected_nonce_commitment


def compute_coefficient_commitments(
    coefficients: tuple[Scalar, ...],
) -> tuple[Point, ...]:
    """Compute Feldman commitments to polynomial coefficients: φⱼ = aⱼ·G.

    Each commitment φⱼ = aⱼ·G hides the coefficient aⱼ while allowing
    public verification. Given a share f(i) and the commitments, anyone can
    check that f(i)·G equals the expected combination of commitments (see
    verify_share). This is the foundation of verifiable secret sharing.

    Parameters:
        coefficients: The polynomial coefficients (a₀, a₁, …, a_{t-1}).

    Returns:
        Tuple of Points, one commitment per coefficient.
    """
    return tuple(int(c) * G for c in coefficients)


def generate_shares(
    coefficients: tuple[Scalar, ...],
    num_participants: int,
) -> tuple[Scalar, ...]:
    """Evaluate the polynomial at each participant's index to produce shares.

    shareⱼ = f(j) for j in 1..num_participants

    Each participant j receives share f(j), the polynomial evaluated at their
    index. Any t of these shares are sufficient to reconstruct the secret f(0)
    via Lagrange interpolation, but fewer than t reveal nothing.

    Parameters:
        coefficients: The polynomial coefficients.
        num_participants: Total number of participants (n).

    Returns:
        Tuple of Scalar shares, one per participant (indexed 1..n).
    """
    return tuple(evaluate_polynomial(coefficients, x) for x in range(1, num_participants + 1))


def verify_share(
    share: Scalar,
    participant_index: int,
    coefficient_commitments: tuple[Point, ...],
) -> bool:
    """Verify a share against coefficient commitments.

    Checks: share·G == ∑(commitmentₖ · index^k) for k in 0..t-1

    This works because if share = f(index), then:
        share·G = f(index)·G = ∑(aₖ·index^k)·G = ∑(aₖ·G · index^k)

    The right-hand side uses only the public commitments (aₖ·G), so anyone
    can verify a share without learning the secret coefficients. This is the
    key property of Feldman's Verifiable Secret Sharing.

    Parameters:
        share: The share value to verify.
        participant_index: The index at which the share was evaluated.
        coefficient_commitments: The public commitments to the polynomial coefficients.

    Returns:
        True if the share is consistent with the commitments, False otherwise.
    """
    expected = derive_public_verification_share(coefficient_commitments, participant_index)
    return int(share) * G == expected


def aggregate_shares(
    own_share: Scalar,
    other_shares: tuple[Scalar, ...],
) -> Scalar:
    """Aggregate received shares: sᵢ = ∑(fⱼ(i)) for all j.

    After receiving one share from each participant (including our own), sum
    them to get our aggregate share of the group secret. This is secure because
    no single share reveals the group secret, and the aggregate share is a
    point on the degree-(t-1) polynomial whose constant term is the group secret.

    Parameters:
        own_share: This participant's self-share fᵢ(i).
        other_shares: Shares received from other participants fⱼ(i) for j ≠ i.

    Returns:
        The aggregate share sᵢ.
    """
    result = own_share
    for share in other_shares:
        result = result + share
    return result


def derive_public_key(
    own_commitment: Point,
    other_commitments: tuple[Point, ...],
) -> Point:
    """Derive the group public key: Y = ∑(φⱼ₀) for all j.

    The group public key is the ∑ of all participants' secret commitments
    (the commitment to the constant term of each polynomial). This equals
    the group secret times G, without anyone knowing the group secret.

    Parameters:
        own_commitment: This participant's secret commitment (φᵢ₀ = a_i_0·G).
        other_commitments: Secret commitments from all other participants.

    Returns:
        The group public key Y.
    """
    public_key = own_commitment
    for commitment in other_commitments:
        public_key = public_key + commitment
    return public_key


def derive_group_commitments(
    own_commitments: tuple[Point, ...],
    other_commitments: tuple[tuple[Point, ...], ...],
    existing: tuple[Point, ...] | None = None,
) -> tuple[Point, ...]:
    """Derive group commitments by summing coefficient commitments across participants.

    Group commitments are the element-wise sum of all participants' coefficient
    commitments. They encode the "shape" of the group polynomial in public form,
    allowing anyone to derive any participant's public verification share.

    If existing group commitments are provided (e.g., from a previous DKG round
    during refresh), the new commitments are added to them element-wise.

    Parameters:
        own_commitments: This participant's coefficient commitments.
        other_commitments: Tuple of other participants' coefficient commitment tuples.
        existing: Optional existing group commitments to accumulate onto.

    Returns:
        The group commitments (one Point per polynomial degree).
    """
    group_commitments = tuple(
        sum(commitments, Point())
        for commitments in zip(
            *(*other_commitments, own_commitments),
            strict=True,
        )
    )

    if existing is not None:
        group_commitments = tuple(
            sum(commitments, Point())
            for commitments in zip(existing, group_commitments, strict=True)
        )

    return group_commitments


def public_verification_share(aggregate_share: Scalar) -> Point:
    """Compute the public verification share: Yᵢ = sᵢ·G.

    This is the public counterpart to a participant's aggregate share. Other
    participants can independently derive this value from the group commitments
    (see derive_public_verification_share) and compare it to verify that a
    participant is using the correct share.

    Parameters:
        aggregate_share: The participant's aggregate secret share sᵢ.

    Returns:
        The public verification share Yᵢ = sᵢ·G.
    """
    return int(aggregate_share) * G


def derive_public_verification_share(
    coefficient_commitments: tuple[Point, ...],
    index: int,
) -> Point:
    """Derive any participant's public verification share from group commitments.

    Yᵢ = ∑(commitmentₖ · index^k) for k in 0..t-1

    This computes what Yᵢ = sᵢ·G would be, using only public information
    (the group commitments). Used to verify that a participant's claimed public
    share matches expectations, without learning their secret share.

    Note: the threshold parameter is implicit in the length of
    coefficient_commitments.

    Parameters:
        coefficient_commitments: The group (or individual) coefficient commitments.
        index: The participant's index.

    Returns:
        The derived public verification share Yᵢ.
    """
    expected_y_commitment = Point()  # Point at infinity
    for k, commitment in enumerate(coefficient_commitments):
        expected_y_commitment += (index**k % Q) * commitment
    return expected_y_commitment
