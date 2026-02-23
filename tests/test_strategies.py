"""Smoke tests verifying each Hypothesis strategy generates valid values."""

from hypothesis import given, settings

from frost import Point, Q, Scalar

from .strategies import messages, points, scalars, scalars_with_zero, threshold_params


@given(s=scalars)
@settings(max_examples=10)
def test_scalars_in_range(s):
    assert isinstance(s, Scalar)
    assert 1 <= s.value <= Q - 1


@given(s=scalars_with_zero)
@settings(max_examples=10)
def test_scalars_with_zero_in_range(s):
    assert isinstance(s, Scalar)
    assert 0 <= s.value <= Q - 1


@given(p=points)
@settings(max_examples=10)
def test_points_on_curve(p):
    assert isinstance(p, Point)
    assert not p.is_zero()


@given(m=messages)
@settings(max_examples=10)
def test_messages_non_empty(m):
    assert isinstance(m, bytes)
    assert len(m) >= 1


@given(params=threshold_params())
@settings(max_examples=10)
def test_threshold_params_valid(params):
    t, n = params
    assert 2 <= t <= n
