"""
This module defines the Point class, which represents points on an elliptic curve.
It includes methods for point arithmetic such as addition, multiplication, and negation,
as well as serialization and deserialization of points for secp256k1, the elliptic curve
used in Bitcoin and other cryptographic applications.

The Point class provides essential operations required for elliptic curve cryptography,
such as point doubling, scalar multiplication, and checks for the point at infinity.
"""

from __future__ import annotations
from typing import Optional
from .constants import P, Q, G_x, G_y


class Point:
    """Class representing an elliptic curve point."""

    def __init__(self, x: Optional[int] = None, y: Optional[int] = None):
        """
        Initialize a point on an elliptic curve.

        Parameters:
        x (Optional[int], optional): The x-coordinate of the point.
            Defaults to None, representing the point at infinity.
        y (Optional[int], optional): The y-coordinate of the point.
            Defaults to None, also representing the point at infinity.

        The point at infinity serves as the identity element in elliptic curve addition.
        """

        self.x = x
        self.y = y

    @classmethod
    def sec_deserialize(cls, hex_public_key: str) -> Point:
        """
        Deserialize a SEC 1 compressed hex-encoded public key to a Point object.

        Parameters:
        hex_public_key (str): Hexadecimal string of 33 bytes representing the compressed public key.

        Returns:
        Point: An instance of Point corresponding to the deserialized public key.

        Raises:
        ValueError: If the input is not a valid hex string, does not represent
        a valid point, or has incorrect length.
        """
        try:
            hex_bytes = bytes.fromhex(hex_public_key)
            if len(hex_bytes) != 33:
                raise ValueError(
                    "Input must be exactly 33 bytes long for SEC 1 compressed format."
                )
            is_even = hex_bytes[0] == 2
            x_bytes = hex_bytes[1:]
            x = int.from_bytes(x_bytes, "big")
            y_squared = (pow(x, 3, P) + 7) % P
            y = pow(y_squared, (P + 1) // 4, P)

            if y % 2 == 0:
                even_y = y
                odd_y = (P - y) % P
            else:
                even_y = (P - y) % P
                odd_y = y
            y = even_y if is_even else odd_y
        except Exception as e:
            raise ValueError(
                "Invalid hex input or unable to compute point from x-coordinate."
            ) from e

        return cls(x, y)

    def sec_serialize(self) -> bytes:
        """
        Serialize the point to its SEC 1 compressed format.

        Returns:
        bytes: The SEC 1 compressed format of the point, consisting of a prefix
        and the x-coordinate.

        Raises:
        ValueError: If the point is at infinity or x, y coordinates are not finite.
        """
        if self.x is None or self.y is None:
            raise ValueError("Cannot serialize the point at infinity.")

        prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
        return prefix + self.x.to_bytes(32, "big")

    @classmethod
    def xonly_deserialize(cls, hex_public_key: str) -> Point:
        """
        Deserialize a point from its x-only hex-encoded representation.

        Parameters:
        hex_public_key (str): The hexadecimal string of 32 bytes representing
        the x-coordinate of the point.

        Returns:
        Point: A Point object corresponding to the deserialized x-coordinate.

        Raises:
        ValueError: If the input is not a valid hex string, does not represent
        a valid point, or has incorrect length.
        """
        try:
            hex_bytes = bytes.fromhex(hex_public_key)
            if len(hex_bytes) != 32:
                raise ValueError(
                    "Input must be exactly 32 bytes long for x-only format."
                )
            x = int.from_bytes(hex_bytes, "big")
            y_squared = (pow(x, 3, P) + 7) % P
            y = pow(y_squared, (P + 1) // 4, P)

            if y % 2 != 0:
                y = (P - y) % P
        except ValueError as e:
            raise ValueError(
                "Invalid hex input or unable to compute point from x-coordinate."
            ) from e

        return cls(x, y)

    def xonly_serialize(self) -> bytes:
        """
        Serialize the x-coordinate of the point to a 32-byte big-endian format.

        Returns:
        bytes: The x-coordinate serialized as a 32-byte big-endian byte string.

        Raises:
        ValueError: If the x-coordinate is not finite.
        """
        if self.x is None:
            raise ValueError("The x-coordinate is not finite.")

        return self.x.to_bytes(32, "big")

    def is_zero(self) -> bool:
        """
        Check if the point is the identity element (point at infinity) in elliptic curve arithmetic.

        Returns:
        bool: True if the point is at infinity, False otherwise.
        """
        return self.x is None or self.y is None

    def __eq__(self, other: object) -> bool:
        """
        Determine if this point is equal to another point by comparing their coordinates.

        Python's default behavior will automatically use this method to
        determine the behavior of __ne__ (not equal) by inverting the result of
        __eq__. Thus, __ne__ does not need to be explicitly defined.

        Parameters:
        other (object): The object to compare with.

        Returns:
        bool: True if both points have the same coordinates, False otherwise.
        """
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __neg__(self) -> Point:
        """
        Negate the point on the elliptic curve.

        Returns:
        Point: A new Point that is the negation of the current point. If the
        current point is at infinity, it returns the point at infinity.

        The negation of a point involves reflecting it over the x-axis, which means the x-coordinate
        remains the same and the y-coordinate is subtracted from the modulus P.
        """
        if self.x is None or self.y is None:
            return self

        return self.__class__(self.x, P - self.y)

    def _dbl(self) -> Point:
        """
        Double the point on the elliptic curve. If the point is at infinity or the y-coordinate
        is zero (implying the point is of order 2), the result is the point at infinity.

        Returns:
        Point: A new Point that is the result of doubling the current point.
        """
        if self.x is None or self.y is None or self.y == 0:
            # Return the point at infinity
            return self.__class__()

        x = self.x
        y = self.y
        s = (3 * x * x * pow(2 * y, P - 2, P)) % P
        sum_x = (s * s - 2 * x) % P
        sum_y = (s * (x - sum_x) - y) % P

        return self.__class__(sum_x, sum_y)

    def __add__(self, other: Point) -> Point:
        """
        Add two points on an elliptic curve.

        Parameters:
        other (Point): Another point to add to this point.

        Returns:
        Point: The sum of the two points as a new Point object.

        Raises:
        ValueError: If other is not a Point or the points cannot be added due to type issues.
        """
        if not isinstance(other, Point):
            raise ValueError("The other object must be an instance of Point")

        if self == other:
            return self._dbl()
        if self.x is None or self.y is None:
            return other
        if other.x is None or other.y is None:
            return self
        if self.x == other.x and self.y != other.y:
            return self.__class__()  # Point at infinity
        s = ((other.y - self.y) * pow(other.x - self.x, P - 2, P)) % P
        sum_x = (s * s - self.x - other.x) % P
        sum_y = (s * (self.x - sum_x) - self.y) % P

        return self.__class__(sum_x, sum_y)

    def __sub__(self, other: Point) -> Point:
        """
        Subtract one point from another on an elliptic curve.

        Parameters:
        other (Point): The point to subtract from this point.

        Returns:
        Point: The result of the point subtraction as a new Point object.

        Raises:
        ValueError: If other is not a Point.
        """
        if not isinstance(other, Point):
            raise ValueError("The other object must be an instance of Point")

        return self + -other

    def __rmul__(self, scalar: int) -> Point:
        """
        Multiply this point by an integer scalar using the double-and-add
        method, reduced modulo the curve order.

        Parameters:
        scalar (int): The scalar to multiply this point by.

        Returns:
        Point: The result of the scalar multiplication.

        Raises:
        ValueError: If the scalar is not an integer.
        """
        # Reduce scalar by the group order to ensure operation within the finite group
        scalar = scalar % Q

        if not isinstance(scalar, int):
            raise ValueError("The scalar must be an integer")

        p = self
        r = self.__class__()
        i = 1

        while i <= scalar:
            if i & scalar:
                r = r + p
            p = p._dbl()
            i <<= 1

        return r

    def __str__(self) -> str:
        """
        Return a human-readable string representation of the point.

        Returns:
        str: A string that represents the point. If the point is at
        infinity, returns 'Point at Infinity'.
        Otherwise, returns the x and y coordinates in hexadecimal format.
        """
        if self.is_zero():
            return "0"
        return f"X: 0x{self.x:x}\nY: 0x{self.y:x}"

    def __repr__(self) -> str:
        """
        Return a machine-readable string representation of the point.
        """
        if self.is_zero():
            return f"{self.__class__.__name__}(x=None, y=None)"
        return f"{self.__class__.__name__}(x={self.x}, y={self.y})"


# The generator point G
G: Point = Point(G_x, G_y)
