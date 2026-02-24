"""
Polynomial operations over the scalar field of secp256k1.

In Shamir's Secret Sharing, each participant generates a random polynomial
f(x) = a₀ + a₁·x + … + a_{t-1}·x^{t-1} of degree (threshold - 1).
The constant term a₀ is the participant's secret. Evaluating f(x) at each
participant's index produces that participant's share of the secret.

Given any t shares (points on the polynomial), the secret a₀ can be recovered
via Lagrange interpolation, but fewer than t shares reveal nothing about it.

This module provides standalone functions for:
- Generating random polynomials (for key generation, refresh, threshold increase)
- Evaluating polynomials at a point (for share generation)

All coefficients are Scalar values (elements of Z_Q), ensuring arithmetic
is always correctly reduced modulo the curve order.

References:
- Shamir, A., "How to Share a Secret," Communications of the ACM,
  vol. 22, no. 11, pp. 612-613, 1979.
- Herzberg, A. et al., "Proactive Secret Sharing Or: How to Cope With
  Perpetual Leakage," CRYPTO '95. (Zero-constant polynomial refresh
  technique, used by generate_refresh_polynomial.)
"""

import secrets

from .constants import Q
from .scalar import Scalar


def generate_polynomial(threshold: int) -> tuple[Scalar, ...]:
    """Generate a random polynomial of degree (threshold - 1).

    In Shamir's Secret Sharing, each participant generates a random polynomial
    f(x) = a₀ + a₁·x + … + a_{t-1}·x^{t-1}, where a₀ is their secret.
    The polynomial is evaluated at each participant's index to produce shares.

    Returns:
        Tuple of Scalar coefficients (a₀, a₁, …, a_{t-1}).
    """
    return tuple(Scalar(secrets.randbits(256) % Q) for _ in range(threshold))


def generate_refresh_polynomial(threshold: int) -> tuple[Scalar, ...]:
    """Generate a refresh polynomial with a₀ = 0.

    Used in proactive secret sharing: refreshing shares without changing
    the shared secret. Setting a₀ = 0 ensures the constant term (the secret)
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

    Horner's method: f(x) = a₀ + x·(a₁ + x·(a₂ + …))
    This is numerically stable and efficient (t multiplications, t additions).
    """
    y = Scalar(0)
    for coefficient in reversed(coefficients):
        y = Scalar(int(y) * x + int(coefficient))
    return y
