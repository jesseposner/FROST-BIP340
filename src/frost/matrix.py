"""
The Matrix module provides classes and utilities for performing various matrix
operations, particularly focusing on applications within finite fields, often
used in cryptographic computations.

This module includes:
- The Matrix class which supports standard matrix operations such as
  multiplication, determinant calculation, and finding the inverse of a matrix,
  all performed under a modular arithmetic system.
- Factory methods for constructing specialized types of matrices like
  Vandermonde matrices, which are useful for solving systems of equations where
  the solution involves polynomial coefficients.

Classes:
- Matrix: Handles creation and manipulation of matrices. Offers methods to
  multiply matrices, calculate determinants, and invert matrices, all within
  the bounds of modular arithmetic defined by the secp256k1 modulus.

Usage:
The Matrix class can be instantiated directly with a 2D tuple representing the
matrix, or via factory methods like `from_vandermonde` which create a
Vandermonde matrix from given indices.
"""

from __future__ import annotations
from typing import Tuple
from .constants import Q
from .point import Point


class Matrix:
    """Class representing a matrix."""

    def __init__(self, matrix: Tuple[Tuple[int, ...], ...]):
        self.matrix = matrix

    @staticmethod
    def create_vandermonde(indices: Tuple[int, ...]) -> Matrix:
        """
        Create a Vandermonde matrix from a series of indices.

        Parameters:
        indices (Tuple[int, ...]): A tuple of integers used as indices in the
        Vandermonde matrix.

        Returns:
        Matrix: An instance of Matrix representing the Vandermonde matrix.
        """
        n = len(indices)
        matrix = tuple(tuple(pow(x, i, Q) for i in range(n)) for x in indices)
        return Matrix(matrix)

    def determinant(self) -> int:
        """
        Calculate the determinant of this matrix using recursion and modulo arithmetic.

        The determinant is computed modulo a predefined constant Q, ensuring
        that all operations are performed within a finite field context,
        suitable for cryptographic applications where modulus operations are
        essential to maintain values within a finite range.

        Returns:
        int: The determinant of the matrix, reduced modulo Q.
        """
        if len(self.matrix) == 1:
            return self.matrix[0][0] % Q
        if len(self.matrix) == 2:
            return (
                self.matrix[0][0] * self.matrix[1][1]
                - self.matrix[0][1] * self.matrix[1][0]
            ) % Q
        det = 0
        for c in range(len(self.matrix)):
            minor = Matrix(tuple(row[:c] + row[c + 1 :] for row in self.matrix[1:]))
            det += ((-1) ** c) * self.matrix[0][c] * minor.determinant() % Q
            det %= Q
        return det

    def mult_point_matrix(
        self, Y: Tuple[Tuple[Point, ...], ...]
    ) -> Tuple[Tuple[Point, ...], ...]:
        """
        Multiply this matrix by a matrix of Point objects, performing scalar
        multiplication and addition of Points.

        Parameters:
        Y (Tuple[Tuple[Point, ...], ...]): A tuple of tuples representing a
        matrix of Point objects.

        Returns:
        Tuple[Tuple[Point, ...], ...]: The resulting matrix from the
        multiplication, each element being a Point.
        """
        result = []
        for a_row in self.matrix:
            row_result = []
            for j in range(len(Y[0])):
                sum_point = Point()  # Point at infinity
                for k, scalar in enumerate(a_row):
                    point = Y[k][j]
                    sum_point += scalar * point
                row_result.append(sum_point)
            result.append(tuple(row_result))
        return tuple(result)

    def inverse_matrix(self) -> Matrix:
        """
        Calculate and return the inverse of this matrix, using modular
        arithmetic.

        The matrix inversion is performed modulo a predefined constant Q. The
        method employs the calculation of minors, cofactors, and the adjugate
        matrix, followed by multiplication by the modular inverse of the
        determinant of the matrix.

        Returns:
        Matrix: A new Matrix instance representing the inverse of this matrix, modulo Q.
        """
        n = len(self.matrix)
        adj = [[0 for _ in range(n)] for _ in range(n)]
        for i in range(n):
            for j in range(n):
                minor = Matrix(
                    tuple(
                        tuple(self.matrix[x][y] for y in range(n) if y != j)
                        for x in range(n)
                        if x != i
                    )
                )
                adj[j][i] = ((-1) ** (i + j)) * minor.determinant() % Q
        det = self.determinant()
        det_inv = pow(det, Q - 2, Q)
        for row in range(n):
            for col in range(n):
                adj[row][col] = (adj[row][col] * det_inv) % Q
        return Matrix(tuple(tuple(row) for row in adj))
