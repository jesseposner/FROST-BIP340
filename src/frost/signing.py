"""
FROST threshold signing protocol.

FROST signing is a two-round protocol where a subset of t participants
(signers) collaborate to produce a Schnorr signature without reconstructing
the shared secret:

Round 1: Each signer generates a nonce pair (dᵢ, eᵢ) and publishes
commitments (Dᵢ, Eᵢ) = (dᵢ·G, eᵢ·G).

Round 2: Each signer computes their signature share:
    zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c

Where:
    dᵢ, eᵢ   = nonce pair (random, single-use)
    ρᵢ        = binding value H(i, m, B) (binds this nonce to this message+group)
    λᵢ        = Lagrange coefficient (this participant's interpolation weight)
    sᵢ        = aggregate share (this participant's secret share)
    c         = challenge hash H(R, Y, m) (BIP340 Schnorr challenge)

The aggregator sums the shares: z = ∑(zᵢ). The final BIP340 signature is
(R, z) where R is the group nonce commitment.

BIP340 compatibility: nonces and keys are negated as needed to ensure even-y
values, matching BIP340's x-only public key convention.

References:
- Komlo, C. and Goldberg, I., "FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures," SAC 2020, LNCS 12804, Section 5.2.
- Connolly, D., Komlo, C., Goldberg, I., and Wood, C. A., "The Flexible
  Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round
  Schnorr Signatures," RFC 9591, June 2024.
- BIP 340: Schnorr Signatures for secp256k1 (Wuille, Nick, Ruffing).
"""

from .aggregator import Aggregator
from .lagrange import lagrange_coefficient
from .point import G, Point
from .scalar import Scalar


def generate_nonce_pair() -> tuple[tuple[Scalar, Scalar], tuple[Point, Point]]:
    """Generate a fresh nonce pair and their commitments for signing.

    Each signer must generate a unique, random nonce pair for every signing
    session. The nonce pair (d, e) is kept secret; their commitments
    (D, E) = (d·G, e·G) are published to other signers.

    Returns:
        ((d, e), (D, E)) where d, e are secret nonces and D = d*G, E = e*G.

    The nonce pair MUST be used at most once. Reusing nonces across different
    signing sessions leaks the signer's secret share, because the attacker
    can set up a system of equations to solve for sᵢ.
    """
    d = Scalar.random()
    e = Scalar.random()
    D = int(d) * G
    E = int(e) * G
    return ((d, e), (D, E))


def sign(
    nonce_pair: tuple[Scalar, Scalar],
    aggregate_share: Scalar,
    public_key: Point,
    participant_index: int,
    message: bytes,
    nonce_commitment_pairs: tuple[tuple[Point, Point], ...],
    participant_indexes: tuple[int, ...],
    bip32_tweak: int | None = None,
    taproot_tweak: int | None = None,
) -> Scalar:
    """Compute this participant's signature share.

    FROST signing equation (Section 5.2 of the FROST paper):
        zᵢ = dᵢ + (eᵢ·ρᵢ) + λᵢ·sᵢ·c

    Where:
        dᵢ, eᵢ   = nonce pair
        ρᵢ        = binding value (commits this nonce to this message+group)
        λᵢ        = Lagrange coefficient (this participant's weight)
        sᵢ        = aggregate share (this participant's secret share)
        c         = challenge hash H(R, Y, m)

    BIP340 adjustments:
    - Nonces are negated if the group commitment R has odd y
    - The aggregate share is negated if the public key has odd y

    These negations ensure the final signature is valid under BIP340's x-only
    public key convention, which requires even-y points.

    Parameters:
        nonce_pair: (dᵢ, eᵢ), the secret nonce pair for this signing session.
        aggregate_share: sᵢ, this participant's secret share.
        public_key: Y, the group public key.
        participant_index: i, this participant's index.
        message: m, the message being signed.
        nonce_commitment_pairs: B, all signers' nonce commitment pairs.
        participant_indexes: S, the set of signer indexes.
        bip32_tweak: Optional BIP32 tweak for key derivation.
        taproot_tweak: Optional Taproot tweak for key derivation.

    Returns:
        zᵢ, this participant's signature share.
    """
    # R = group nonce commitment
    group_commitment = Aggregator.group_commitment(
        message, nonce_commitment_pairs, participant_indexes
    )
    if group_commitment.x is None or group_commitment.y is None:
        raise ValueError("Group commitment is the point at infinity.")

    tweaked_key = public_key
    parity = 0
    if bip32_tweak is not None and taproot_tweak is not None:
        tweaked_key, parity = Aggregator.tweak_key(bip32_tweak, taproot_tweak, public_key)

    # c = H₂(R, Y, m) — the BIP340 Schnorr challenge
    challenge_hash = Aggregator.challenge_hash(group_commitment, tweaked_key, message)

    # dᵢ, eᵢ
    first_nonce, second_nonce = nonce_pair

    # Negate nonces if R has odd y (BIP340 requires even y for R)
    if group_commitment.y % 2 != 0:
        first_nonce = -first_nonce
        second_nonce = -second_nonce

    # ρᵢ = H₁(i, m, B) — binding value
    binding_value = Aggregator.binding_value(
        participant_index, message, nonce_commitment_pairs, participant_indexes
    )

    # λᵢ — Lagrange coefficient
    lam = lagrange_coefficient(participant_indexes, participant_index)

    # sᵢ — aggregate share, possibly negated for BIP340
    share = aggregate_share
    if tweaked_key.y is None:
        raise ValueError("Public key is the point at infinity.")
    if tweaked_key.y % 2 != parity:
        share = -share

    # FROST signing equation: zᵢ = dᵢ + (eᵢ·ρᵢ) + λᵢ·sᵢ·c
    # binding_value and challenge_hash are ints from Aggregator, wrap in Scalar
    binding = Scalar(binding_value)
    challenge = Scalar(challenge_hash)
    return first_nonce + second_nonce * binding + lam * share * challenge
