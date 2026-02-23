"""Reusable Hypothesis strategies for property-based testing of crypto primitives."""

from hypothesis import strategies as st

from frost import G, Participant, Q, Scalar

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


@st.composite
def dkg_group(draw, max_n=4):
    """A complete DKG group with threshold t and n participants.

    Expensive (~1s for n=4). Use @settings(max_examples=10, deadline=None).
    """
    t, n = draw(threshold_params(max_n=max_n))
    participants = [Participant(index=i + 1, threshold=t, participants=n) for i in range(n)]

    for p in participants:
        p.init_keygen()
    for p in participants:
        p.generate_shares()

    for p in participants:
        other_shares = tuple(
            other.shares[p.index - 1] for other in participants if other.index != p.index
        )
        p.aggregate_shares(other_shares)

    for p in participants:
        other_commitments = tuple(
            other.coefficient_commitments[0] for other in participants if other.index != p.index
        )
        p.derive_public_key(other_commitments)

    # All participants agree on the public key
    for p in participants[1:]:
        assert p.public_key == participants[0].public_key

    for p in participants:
        other_cc = tuple(
            other.coefficient_commitments for other in participants if other.index != p.index
        )
        p.derive_group_commitments(other_cc)

    return participants, t, n
