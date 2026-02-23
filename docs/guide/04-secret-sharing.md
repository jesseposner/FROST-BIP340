# Shamir's Secret Sharing

This chapter explains how a secret can be split among n participants such that
any t can reconstruct it, but fewer than t learn nothing. This is the
cryptographic backbone of FROST's key distribution.

## The Core Idea

A line (degree-1 polynomial) is determined by 2 points. A parabola (degree-2
polynomial) is determined by 3 points. In general, a degree-(t-1) polynomial
has t unknowns (its coefficients), so exactly t points determine it uniquely,
but t-1 points leave one degree of freedom: the secret remains completely
hidden.

Shamir's Secret Sharing exploits this: encode the secret as the constant term
of a random degree-(t-1) polynomial, then distribute evaluations of that
polynomial as shares.

## Polynomial Evaluation

A polynomial of degree (t-1) has the form:

    f(x) = a₀ + a₁·x + a₂·x² + … + a_{t-1}·x^{t-1}

The coefficients a₀, a₁, ..., a_{t-1} are random scalars in Z_Q. The constant
term a₀ is the secret. The other coefficients are random "noise" that protects
the secret.

```python
from frost.polynomial import generate_polynomial

# Generate a random polynomial of degree 2 (threshold = 3)
coefficients = generate_polynomial(threshold=3)
# coefficients = (a₀, a₁, a₂) where a₀ is the secret
```

## Shares as Evaluations

Each participant i receives the value f(i): the polynomial evaluated at their
index. For a 2-of-3 scheme:

    f(1) = a₀ + a₁·1 + a₂·1²
    f(2) = a₀ + a₁·2 + a₂·2²
    f(3) = a₀ + a₁·3 + a₂·3²

Each share is a single scalar. No individual share reveals a₀ (the secret),
because each evaluation mixes a₀ with the unknown random coefficients.

```python
from frost.polynomial import evaluate_polynomial

share_1 = evaluate_polynomial(coefficients, x=1)
share_2 = evaluate_polynomial(coefficients, x=2)
share_3 = evaluate_polynomial(coefficients, x=3)
```

## Lagrange Interpolation

Given t points on a degree-(t-1) polynomial, Lagrange interpolation recovers
the polynomial exactly. To reconstruct the secret, we only need f(0): the
constant term.

The idea: construct t basis polynomials, each passing through exactly one of
the known points and evaluating to zero at all the others. The sum of these
basis polynomials, weighted by the known y-values, reproduces the original
polynomial.

## The Lagrange Coefficient Formula

For participant i, the Lagrange coefficient at evaluation point x is:

    λᵢ(x) = ∏((x - xⱼ) / (xᵢ - xⱼ)) for all j ≠ i

where the product runs over all other participants in the interpolation set.

The reconstructed value at x is:

    f(x) = ∑(λᵢ(x) · f(xᵢ))

Each share f(xᵢ) is multiplied by its Lagrange coefficient λᵢ and the results
are summed. The coefficients are determined entirely by the set of participant
indexes, not by the shares themselves.

```python
from frost.lagrange import lagrange_coefficient

# For participants {1, 2, 3}, compute participant 1's coefficient at x=0
lam_1 = lagrange_coefficient(
    participant_indexes=(1, 2, 3),
    participant_index=1,
    x=0,
)
```

## Why x=0?

The secret is a₀ = f(0). Evaluating the interpolation formula at x=0
recovers the constant term directly:

    f(0) = ∑(λᵢ(0) · f(i))

This is why `lagrange_coefficient` defaults to x=0: the most common use case
is secret reconstruction. FROST signing also uses Lagrange coefficients (at
x=0) to weight each participant's signature share so the partial signatures
combine into a valid group signature.

## Worked Example: 2-of-3 Sharing

Let's trace through a small example. Suppose:
- Threshold t = 2 (degree-1 polynomial: a line)
- Participants n = 3
- Secret a₀ = 5
- Random coefficient a₁ = 3

The polynomial is f(x) = 5 + 3·x. The shares:
- f(1) = 5 + 3·1 = 8
- f(2) = 5 + 3·2 = 11
- f(3) = 5 + 3·3 = 14

**Reconstruction from shares 1 and 2:**

    λ₁(0) = (0 - 2) / (1 - 2) = -2 / -1 = 2
    λ₂(0) = (0 - 1) / (2 - 1) = -1 / 1 = -1

    f(0) = λ₁·f(1) + λ₂·f(2) = 2·8 + (-1)·11 = 16 - 11 = 5  ✓

**Reconstruction from shares 2 and 3:**

    λ₂(0) = (0 - 3) / (2 - 3) = -3 / -1 = 3
    λ₃(0) = (0 - 2) / (3 - 2) = -2 / 1 = -2

    f(0) = λ₂·f(2) + λ₃·f(3) = 3·11 + (-2)·14 = 33 - 28 = 5  ✓

Any 2 of the 3 shares reconstruct the secret. A single share (say f(1) = 8)
reveals nothing: infinitely many lines pass through the point (1, 8), each
with a different y-intercept.

(In the real implementation, all arithmetic is modulo Q, so the values wrap
around within the scalar field.)

## The Threshold Property

The security of the scheme follows directly from polynomial algebra:
- **t shares**: determine a unique degree-(t-1) polynomial, so the secret is
  fully determined. Reconstruction succeeds.
- **t-1 shares**: leave one degree of freedom. For every possible secret
  value, there exists a consistent polynomial. The shares carry zero
  information about which secret is the real one.

This is *information-theoretic* security: it holds regardless of computational
power. Even an attacker with unlimited computing resources cannot extract the
secret from fewer than t shares.

## Horner's Method

The implementation evaluates polynomials using Horner's method, which rewrites
the polynomial in nested form:

    f(x) = a₀ + x·(a₁ + x·(a₂ + … + x·a_{t-1}…))

This requires only t multiplications and t additions (compared to the naive
form, which needs additional exponentiation). See `evaluate_polynomial` in
`polynomial.py`.

## Summary

| Concept | Code reference | Purpose |
|---------|---------------|---------|
| Generate polynomial | `polynomial.generate_polynomial()` | Create random polynomial with secret as a₀ |
| Evaluate at index | `polynomial.evaluate_polynomial()` | Compute participant's share f(i) |
| Lagrange coefficient | `lagrange.lagrange_coefficient()` | Compute participant's interpolation weight |
| Secret reconstruction | ∑(λᵢ·f(i)) at x=0 | Recover a₀ from t shares |

Shamir's scheme distributes a secret securely, but participants must trust that
the dealer generated the shares honestly. How do you verify a share without
seeing the polynomial? That's the problem polynomial commitments solve, covered
in the next chapter.
