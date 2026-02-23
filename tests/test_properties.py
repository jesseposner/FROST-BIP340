"""Property-based tests for FROST protocol invariants.

These tests use Hypothesis to verify that algebraic and protocol properties
hold for arbitrary inputs, not just the specific examples in other test files.

Tests involving DKG are expensive (~1s per example in pure Python).
Use @settings(max_examples=10, deadline=None) for these.
"""

from hypothesis import given, settings

from frost import Point
from tests.strategies import points


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
