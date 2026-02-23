import secrets

import pytest

from frost import Aggregator, G, Point, Q


def test_sign(keygen_group):
    p1, p2, p3 = keygen_group

    pk = p1.public_key

    # NonceGen
    p1.generate_nonce_pair()
    p2.generate_nonce_pair()
    p3.generate_nonce_pair()

    # Sign
    msg = b"fnord!"
    participant_indexes = (1, 2)
    agg = Aggregator(
        pk,
        msg,
        (p1.nonce_commitment_pair, p2.nonce_commitment_pair),
        participant_indexes,
    )
    message, nonce_commitment_pairs = agg.signing_inputs()

    s1 = p1.sign(message, nonce_commitment_pairs, participant_indexes)
    s2 = p2.sign(message, nonce_commitment_pairs, participant_indexes)

    # σ = (R, z)
    sig = agg.signature((s1, s2))
    sig_bytes = bytes.fromhex(sig)
    nonce_commitment = Point.from_bytes_xonly(sig_bytes[0:32].hex())
    z = int.from_bytes(sig_bytes[32:64], "big")

    # verify: c = H_2(R, Y, m)
    challenge_hash = Aggregator.challenge_hash(nonce_commitment, pk, msg)
    # Negate Y if Y.y is odd
    if pk.y % 2 != 0:
        pk = -pk

    # R ≟ g^z * Y^-c
    assert nonce_commitment == (z * G) + (Q - challenge_hash) * pk


def test_tweaking(keygen_group):
    p1, p2, p3 = keygen_group

    pk = p1.public_key

    # NonceGen
    p1.generate_nonce_pair()
    p2.generate_nonce_pair()
    p3.generate_nonce_pair()

    # Sign
    msg = b"fnord!"
    participant_indexes = (1, 2)
    bip32_tweak = secrets.randbits(256) % Q
    taproot_tweak = secrets.randbits(256) % Q
    agg = Aggregator(
        pk,
        msg,
        (p1.nonce_commitment_pair, p2.nonce_commitment_pair),
        participant_indexes,
        bip32_tweak,
        taproot_tweak,
    )
    message, nonce_commitment_pairs = agg.signing_inputs()

    s1 = p1.sign(
        message,
        nonce_commitment_pairs,
        participant_indexes,
        bip32_tweak,
        taproot_tweak,
    )
    s2 = p2.sign(
        message,
        nonce_commitment_pairs,
        participant_indexes,
        bip32_tweak,
        taproot_tweak,
    )

    # σ = (R, z)
    sig = agg.signature((s1, s2))
    sig_bytes = bytes.fromhex(sig)
    nonce_commitment = Point.from_bytes_xonly(sig_bytes[0:32].hex())
    z = int.from_bytes(sig_bytes[32:64], "big")

    # verify
    tweaked_pk = pk + (bip32_tweak * G)
    if tweaked_pk.y % 2 != 0:
        tweaked_pk = -tweaked_pk
    tweaked_pk = tweaked_pk + (taproot_tweak * G)
    if tweaked_pk.y % 2 != 0:
        tweaked_pk = -tweaked_pk
    # c = H_2(R, Y, m)
    challenge_hash = Aggregator.challenge_hash(nonce_commitment, tweaked_pk, msg)
    # R ≟ g^z * Y^-c
    assert nonce_commitment == (z * G) + (Q - challenge_hash) * tweaked_pk


def test_share_verification(keygen_group):
    """Valid shares pass verification, corrupted share is detected."""
    p1, p2, _p3 = keygen_group

    p1.generate_nonce_pair()
    p2.generate_nonce_pair()

    msg = b"test share verification"
    participant_indexes = (1, 2)
    nonce_pairs = (p1.nonce_commitment_pair, p2.nonce_commitment_pair)

    s1 = p1.sign(msg, nonce_pairs, participant_indexes)
    s2 = p2.sign(msg, nonce_pairs, participant_indexes)

    # Valid shares: aggregation succeeds with group_commitments
    agg = Aggregator(
        p1.public_key,
        msg,
        nonce_pairs,
        participant_indexes,
        group_commitments=p1.group_commitments,
    )
    sig = agg.signature((s1, s2))
    # Verify the signature is valid (BIP340)
    sig_bytes = bytes.fromhex(sig)
    R = Point.from_bytes_xonly(sig_bytes[:32].hex())
    z = int.from_bytes(sig_bytes[32:], "big")
    c = Aggregator.challenge_hash(R, p1.public_key, msg)
    pk = p1.public_key
    if pk.y % 2 != 0:
        pk = -pk
    assert (z * G) + (Q - c) * pk == R

    # Corrupted share: should raise ValueError
    corrupted_s1 = (s1 + 1) % Q
    agg2 = Aggregator(
        p1.public_key,
        msg,
        nonce_pairs,
        participant_indexes,
        group_commitments=p1.group_commitments,
    )
    with pytest.raises(ValueError, match="Invalid signature share"):
        agg2.signature((corrupted_s1, s2))


def test_share_verification_with_tweaks(keygen_group):
    """Share verification works with BIP32 and Taproot tweaks."""
    p1, p2, _p3 = keygen_group

    p1.generate_nonce_pair()
    p2.generate_nonce_pair()

    msg = b"tweaked share verification"
    participant_indexes = (1, 2)
    nonce_pairs = (p1.nonce_commitment_pair, p2.nonce_commitment_pair)
    bip32_tweak = secrets.randbits(256) % Q
    taproot_tweak = secrets.randbits(256) % Q

    s1 = p1.sign(msg, nonce_pairs, participant_indexes, bip32_tweak, taproot_tweak)
    s2 = p2.sign(msg, nonce_pairs, participant_indexes, bip32_tweak, taproot_tweak)

    agg = Aggregator(
        p1.public_key,
        msg,
        nonce_pairs,
        participant_indexes,
        bip32_tweak,
        taproot_tweak,
        group_commitments=p1.group_commitments,
    )
    sig = agg.signature((s1, s2))
    assert len(sig) == 128  # 64 bytes hex-encoded
