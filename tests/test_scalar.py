"""Tests for the Scalar class (Z_Q arithmetic)."""

import pytest
from hypothesis import given, settings

from frost import G, Q
from frost.scalar import Scalar
from tests.strategies import scalars, scalars_with_zero


class TestConstruction:
    def test_basic_value(self):
        assert Scalar(42).value == 42

    def test_reduction_mod_q(self):
        assert Scalar(Q + 5).value == 5

    def test_zero(self):
        assert Scalar(0).value == 0

    def test_q_minus_one(self):
        assert Scalar(Q - 1).value == Q - 1

    def test_q_is_zero(self):
        assert Scalar(Q) == Scalar(0)

    def test_negative_wraps(self):
        assert Scalar(-1).value == Q - 1

    def test_type_error_on_string(self):
        with pytest.raises(TypeError, match="integer"):
            Scalar("not an int")

    def test_type_error_on_float(self):
        with pytest.raises(TypeError, match="integer"):
            Scalar(3.14)


class TestArithmetic:
    def test_add(self):
        a, b = 7, 13
        assert Scalar(a) + Scalar(b) == Scalar((a + b) % Q)

    def test_add_wraps(self):
        assert Scalar(Q - 1) + Scalar(2) == Scalar(1)

    def test_sub(self):
        a, b = 20, 7
        assert Scalar(a) - Scalar(b) == Scalar((a - b) % Q)

    def test_sub_wraps(self):
        assert Scalar(3) - Scalar(5) == Scalar((3 - 5) % Q)

    def test_mul(self):
        a, b = 6, 7
        assert Scalar(a) * Scalar(b) == Scalar((a * b) % Q)

    def test_neg(self):
        x = 42
        assert Scalar(x) + (-Scalar(x)) == Scalar(0)

    def test_neg_zero(self):
        assert -Scalar(0) == Scalar(0)

    def test_no_implicit_int_add(self):
        with pytest.raises(TypeError):
            Scalar(3) + 5

    def test_no_implicit_int_mul(self):
        # Scalar * int returns NotImplemented, which Python turns into TypeError
        with pytest.raises(TypeError):
            Scalar(3) * 5

    def test_scalar_times_point(self):
        # Scalar * Point falls through to Point.__rmul__ via NotImplemented
        assert Scalar(5) * G == 5 * G


class TestInverse:
    def test_inverse(self):
        x = Scalar(42)
        assert x * x.inv() == Scalar(1)

    def test_inverse_large(self):
        x = Scalar(Q - 1)
        assert x * x.inv() == Scalar(1)

    def test_inverse_one(self):
        assert Scalar(1).inv() == Scalar(1)

    def test_inverse_zero_raises(self):
        with pytest.raises(ValueError, match="Cannot invert zero"):
            Scalar(0).inv()


class TestConversions:
    def test_int_conversion(self):
        assert int(Scalar(99)) == 99

    def test_int_conversion_reduced(self):
        assert int(Scalar(Q + 7)) == 7

    def test_bool_zero_is_false(self):
        assert not bool(Scalar(0))

    def test_bool_nonzero_is_true(self):
        assert bool(Scalar(1))
        assert bool(Scalar(Q - 1))

    def test_repr(self):
        assert repr(Scalar(42)) == "Scalar(42)"

    def test_to_bytes(self):
        b = Scalar(1).to_bytes()
        assert len(b) == 32
        assert b[-1] == 1
        assert all(x == 0 for x in b[:-1])


class TestEquality:
    def test_scalar_equality(self):
        assert Scalar(10) == Scalar(10)

    def test_scalar_inequality(self):
        assert Scalar(10) != Scalar(11)

    def test_int_comparison(self):
        assert Scalar(10) == 10

    def test_hash_consistent(self):
        assert hash(Scalar(42)) == hash(Scalar(42))

    def test_hash_in_set(self):
        s = {Scalar(1), Scalar(2), Scalar(1)}
        assert len(s) == 2


class TestRandom:
    def test_random_returns_scalar(self):
        r = Scalar.random()
        assert isinstance(r, Scalar)

    def test_random_in_range(self):
        for _ in range(10):
            r = Scalar.random()
            assert 0 <= r.value < Q

    def test_random_not_all_same(self):
        samples = [Scalar.random().value for _ in range(5)]
        assert len(set(samples)) > 1


class TestPropertyBased:
    @given(a=scalars_with_zero, b=scalars_with_zero, c=scalars_with_zero)
    def test_addition_associative(self, a, b, c):
        assert (a + b) + c == a + (b + c)

    @given(a=scalars_with_zero, b=scalars_with_zero)
    def test_addition_commutative(self, a, b):
        assert a + b == b + a

    @given(a=scalars_with_zero)
    def test_additive_identity(self, a):
        assert a + Scalar(0) == a

    @given(a=scalars_with_zero)
    def test_additive_inverse(self, a):
        assert a + (-a) == Scalar(0)

    @given(a=scalars, b=scalars)
    def test_multiplication_commutative(self, a, b):
        assert a * b == b * a

    @given(a=scalars, b=scalars, c=scalars)
    def test_multiplication_associative(self, a, b, c):
        assert (a * b) * c == a * (b * c)

    @given(a=scalars)
    def test_multiplicative_identity(self, a):
        assert a * Scalar(1) == a

    @given(a=scalars)
    def test_multiplicative_inverse(self, a):
        assert a * a.inv() == Scalar(1)

    @given(a=scalars, b=scalars, c=scalars)
    def test_distributive(self, a, b, c):
        assert a * (b + c) == (a * b) + (a * c)

    @given(s=scalars)
    @settings(deadline=None)
    def test_scalar_point_consistency(self, s):
        """Scalar * G via Scalar matches int * G."""
        assert s * G == int(s) * G
