"""
Distributed Key Generation (DKG) for FROST threshold signatures.

DKG allows n participants to jointly generate a shared secret key without any
single participant knowing the full secret. Each participant:
1. Generates a random polynomial and commits to its coefficients
2. Proves knowledge of their secret (the constant term)
3. Evaluates their polynomial at each other participant's index to create shares
4. Distributes shares to other participants (verified against commitments)
5. Aggregates received shares into their private share of the group secret

The result: each participant holds a secret share s_i such that the shared
secret (the sum of all participants' constant terms) can be reconstructed
from any t shares via Lagrange interpolation, but fewer than t shares reveal
nothing.

References:
- FROST paper (Komlo & Goldberg), Section 5.1: Key Generation
- Pedersen's DKG (1991), which FROST builds upon
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
        sigma_i = (R_i, mu_i) where R_i = k*G, mu_i = k + a_i_0 * c_i
    and c_i = H(i, context, a_i_0*G, R_i).

    The proof structure is a standard Schnorr signature of knowledge:
    - The prover picks a random nonce k, publishes R = k*G
    - The challenge c binds the prover's identity (index), the context string,
      and both the secret commitment and nonce commitment
    - The response mu = k + secret * c proves knowledge of the secret

    Parameters:
        secret: The secret coefficient a_i_0 (constant term of the polynomial).
        index: The participant's unique index (1-indexed).
        context: Domain separation string for the challenge hash.

    Returns:
        (R, mu): The nonce commitment and the Schnorr response.
    """
    # k <- Z_q (random nonce)
    nonce = Scalar.random()
    # R_i = g^k (nonce commitment)
    nonce_commitment = int(nonce) * G
    # Build the challenge: c_i = H(i, context, g^a_i_0, R_i)
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

    # mu_i = k + a_i_0 * c_i (Schnorr signature equation, mod Q)
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
        R_i == mu_i * G - c_i * commitment

    This is algebraically equivalent to checking R = g^mu * phi^{-c}, which
    holds only if the prover knew the secret when constructing mu.

    Parameters:
        proof: (R, mu) where R is the nonce commitment and mu is the response.
        secret_commitment: The public commitment to the secret (a_i_0 * G).
        index: The participant's unique index.
        context: Domain separation string (must match what the prover used).

    Returns:
        True if the proof is valid, False otherwise.
    """
    nonce_commitment, mu = proof
    # Reconstruct the challenge: c_i = H(i, context, g^a_i_0, R_i)
    index_byte = index.to_bytes(1, "big")
    secret_commitment_bytes = secret_commitment.to_bytes_compressed()
    nonce_commitment_bytes = nonce_commitment.to_bytes_compressed()

    challenge_input = index_byte + context + secret_commitment_bytes + nonce_commitment_bytes
    challenge_hash_int = int.from_bytes(sha256(challenge_input).digest(), "big")

    # Verify: R_i == mu_i * G - c_i * commitment
    # Rewritten as: R_i == mu*G + (Q - c)*commitment (negation in the scalar field)
    expected_nonce_commitment = (int(mu) * G) + ((Q - challenge_hash_int) * secret_commitment)
    return nonce_commitment == expected_nonce_commitment


def compute_coefficient_commitments(
    coefficients: tuple[Scalar, ...],
) -> tuple[Point, ...]:
    """Compute Pedersen commitments to polynomial coefficients: phi_j = a_j * G.

    Each commitment phi_j = a_j * G hides the coefficient a_j while allowing
    public verification. Given a share f(i) and the commitments, anyone can
    check that f(i) * G equals the expected combination of commitments (see
    verify_share). This is the foundation of verifiable secret sharing.

    Parameters:
        coefficients: The polynomial coefficients (a_0, a_1, ..., a_{t-1}).

    Returns:
        Tuple of Points, one commitment per coefficient.
    """
    return tuple(int(c) * G for c in coefficients)


def generate_shares(
    coefficients: tuple[Scalar, ...],
    num_participants: int,
) -> tuple[Scalar, ...]:
    """Evaluate the polynomial at each participant's index to produce shares.

    share_j = f(j) for j in 1..num_participants

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

    Checks: share * G == sum(commitment_k * index^k for k in 0..t-1)

    This works because if share = f(index), then:
        share * G = f(index) * G = sum(a_k * index^k) * G = sum(a_k*G * index^k)

    The right-hand side uses only the public commitments (a_k * G), so anyone
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
    """Aggregate received shares: s_i = sum(f_j(i)) for all j.

    After receiving one share from each participant (including our own), sum
    them to get our aggregate share of the group secret. This is secure because
    no single share reveals the group secret, and the aggregate share is a
    point on the degree-(t-1) polynomial whose constant term is the group secret.

    Parameters:
        own_share: This participant's self-share f_i(i).
        other_shares: Shares received from other participants f_j(i) for j != i.

    Returns:
        The aggregate share s_i.
    """
    result = own_share
    for share in other_shares:
        result = result + share
    return result


def derive_public_key(
    own_commitment: Point,
    other_commitments: tuple[Point, ...],
) -> Point:
    """Derive the group public key: Y = sum(phi_j_0) for all j.

    The group public key is the sum of all participants' secret commitments
    (the commitment to the constant term of each polynomial). This equals
    the group secret times G, without anyone knowing the group secret.

    Parameters:
        own_commitment: This participant's secret commitment (phi_i_0 = a_i_0 * G).
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
    """Compute the public verification share: Y_i = s_i * G.

    This is the public counterpart to a participant's aggregate share. Other
    participants can independently derive this value from the group commitments
    (see derive_public_verification_share) and compare it to verify that a
    participant is using the correct share.

    Parameters:
        aggregate_share: The participant's aggregate secret share s_i.

    Returns:
        The public verification share Y_i = s_i * G.
    """
    return int(aggregate_share) * G


def derive_public_verification_share(
    coefficient_commitments: tuple[Point, ...],
    index: int,
) -> Point:
    """Derive any participant's public verification share from group commitments.

    Y_i = sum(commitment_k * index^k) for k in 0..t-1

    This computes what Y_i = s_i * G would be, using only public information
    (the group commitments). Used to verify that a participant's claimed public
    share matches expectations, without learning their secret share.

    Note: the threshold parameter is implicit in the length of
    coefficient_commitments.

    Parameters:
        coefficient_commitments: The group (or individual) coefficient commitments.
        index: The participant's index.

    Returns:
        The derived public verification share Y_i.
    """
    expected_y_commitment = Point()  # Point at infinity
    for k, commitment in enumerate(coefficient_commitments):
        expected_y_commitment += (index**k % Q) * commitment
    return expected_y_commitment
