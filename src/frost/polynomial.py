"""
Polynomial operations over the scalar field of secp256k1.

In Shamir's Secret Sharing, each participant generates a random polynomial
f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1} of degree (threshold - 1).
The constant term a_0 is the participant's secret. Evaluating f(x) at each
participant's index produces that participant's share of the secret.

Given any t shares (points on the polynomial), the secret a_0 can be recovered
via Lagrange interpolation, but fewer than t shares reveal nothing about it.

This module provides standalone functions for:
- Generating random polynomials (for key generation, refresh, threshold increase)
- Evaluating polynomials at a point (for share generation)

All coefficients are Scalar values (elements of Z_Q), ensuring arithmetic
is always correctly reduced modulo the curve order.
"""

import secrets

from .constants import Q
from .scalar import Scalar


def generate_polynomial(threshold: int) -> tuple[Scalar, ...]:
    """Generate a random polynomial of degree (threshold - 1).

    In Shamir's Secret Sharing, each participant generates a random polynomial
    f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}, where a_0 is their secret.
    The polynomial is evaluated at each participant's index to produce shares.

    Returns:
        Tuple of Scalar coefficients (a_0, a_1, ..., a_{t-1}).
    """
    return tuple(Scalar(secrets.randbits(256) % Q) for _ in range(threshold))


def generate_refresh_polynomial(threshold: int) -> tuple[Scalar, ...]:
    """Generate a refresh polynomial with a_0 = 0.

    Used in proactive secret sharing: refreshing shares without changing
    the shared secret. Setting a_0 = 0 ensures the constant term (the secret)
    is unchanged when refresh shares are added to existing shares.
    """
    rest = tuple(Scalar(secrets.randbits(256) % Q) for _ in range(threshold - 1))
    return (Scalar(0), *rest)


def generate_threshold_increase_polynomial(new_threshold: int) -> tuple[Scalar, ...]:
    """Generate a polynomial for threshold increase.

    Degree is (new_threshold - 2) because the existing shares already
    encode a polynomial of degree (old_threshold - 1).
    """
    return tuple(Scalar(secrets.randbits(256) % Q) for _ in range(new_threshold - 1))


def evaluate_polynomial(coefficients: tuple[Scalar, ...], x: int) -> Scalar:
    """Evaluate polynomial at point x using Horner's method.

    Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ...))
    This is numerically stable and efficient (t multiplications, t additions).
    """
    y = Scalar(0)
    for coefficient in reversed(coefficients):
        y = Scalar(int(y) * x + int(coefficient))
    return y
