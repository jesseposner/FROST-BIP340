"""Property-based tests for FROST protocol invariants.

These tests use Hypothesis to verify that algebraic and protocol properties
hold for arbitrary inputs, not just the specific examples in other test files.

Tests involving DKG are expensive (~1s per example in pure Python).
Use @settings(max_examples=10, deadline=None) for these.
"""

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from frost import Aggregator, G, Point, Q
from frost.lagrange import lagrange_coefficient
from frost.scalar import Scalar
from tests.strategies import dkg_group, messages, points


@given(p=points)
@settings(deadline=None)
def test_compressed_roundtrip(p):
    """decode(encode(point)) == point for compressed serialization."""
    assert Point.from_bytes_compressed(p.to_bytes_compressed().hex()) == p


@given(p=points)
@settings(deadline=None)
def test_xonly_roundtrip(p):
    """decode(encode(point)) recovers the even-y variant (x-only drops sign)."""
    recovered = Point.from_bytes_xonly(p.to_bytes_xonly().hex())
    assert recovered.x == p.x
    assert recovered.has_even_y()


@settings(max_examples=10, deadline=None)
@given(data=st.data())
def test_threshold_invariant(data):
    """Any t-of-n subset of shares reconstructs the same group secret."""
    participants, t, n = data.draw(dkg_group(max_n=4))
    pk = participants[0].public_key

    all_combos = list(itertools.combinations(range(n), t))
    if len(all_combos) < 2:
        return  # Only one possible subset, nothing to compare

    combo1_idx, combo2_idx = data.draw(
        st.sampled_from(
            [(i, j) for i in range(len(all_combos)) for j in range(i + 1, len(all_combos))]
        )
    )
    combo1 = all_combos[combo1_idx]
    combo2 = all_combos[combo2_idx]

    for combo in [combo1, combo2]:
        subset = [participants[i] for i in combo]
        indexes = tuple(p.index for p in subset)
        secret = Scalar(0)
        for p in subset:
            lam = lagrange_coefficient(indexes, p.index)
            secret = secret + lam * Scalar(p.aggregate_share)
        assert int(secret) * G == pk


@settings(max_examples=10, deadline=None)
@given(data=st.data())
def test_signature_validity(data):
    """Aggregated threshold signature verifies under group public key."""
    participants, t, n = data.draw(dkg_group(max_n=4))
    msg = data.draw(messages)

    # Generate nonce pairs for all participants (Aggregator indexes by participant number)
    for p in participants:
        p.generate_nonce_pair()
    all_nonce_pairs = tuple(p.nonce_commitment_pair for p in participants)

    # Pick a t-sized signer subset
    all_combos = list(itertools.combinations(range(n), t))
    combo = all_combos[data.draw(st.integers(min_value=0, max_value=len(all_combos) - 1))]
    signers = [participants[i] for i in combo]
    signer_indexes = tuple(p.index for p in signers)

    shares = tuple(p.sign(msg, all_nonce_pairs, signer_indexes) for p in signers)

    agg = Aggregator(signers[0].public_key, msg, all_nonce_pairs, signer_indexes)
    sig = agg.signature(shares)

    # BIP340 verification
    sig_bytes = bytes.fromhex(sig)
    R = Point.from_bytes_xonly(sig_bytes[:32].hex())
    z = int.from_bytes(sig_bytes[32:], "big")
    pk = signers[0].public_key
    c = Aggregator.challenge_hash(R, pk, msg)
    if pk.y % 2 != 0:
        pk = -pk
    assert (z * G) + (Q - c) * pk == R
