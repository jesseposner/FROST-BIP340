"""Property-based tests for FROST protocol invariants.

These tests use Hypothesis to verify that algebraic and protocol properties
hold for arbitrary inputs, not just the specific examples in other test files.

Tests involving DKG are expensive (~1s per example in pure Python).
Use @settings(max_examples=10, deadline=None) for these.
"""

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from frost import G, Point
from frost.lagrange import lagrange_coefficient
from frost.scalar import Scalar
from tests.strategies import dkg_group, points


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
