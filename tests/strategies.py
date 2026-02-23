"""Reusable Hypothesis strategies for property-based testing of crypto primitives."""

from hypothesis import strategies as st

from frost import G, Q, Scalar

# Non-zero scalars: elements of Z_Q*
scalars = st.integers(min_value=1, max_value=Q - 1).map(Scalar)

# Scalars including zero
scalars_with_zero = st.integers(min_value=0, max_value=Q - 1).map(Scalar)

# Valid curve points (always on the curve by construction)
points = scalars.map(lambda s: int(s) * G)

# Arbitrary messages (bounded size for speed)
messages = st.binary(min_size=1, max_size=256)


@st.composite
def threshold_params(draw, max_n=5):
    """Generate valid (threshold, num_participants) pairs with 2 <= t <= n."""
    n = draw(st.integers(min_value=2, max_value=max_n))
    t = draw(st.integers(min_value=2, max_value=n))
    return t, n
