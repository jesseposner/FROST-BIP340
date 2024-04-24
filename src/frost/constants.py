"""
These constants define the elliptic curve secp256k1, widely used in cryptographic
applications, including Bitcoin. The curve operates over a finite field of prime
order P, with a base point G of order Q, specified by its coordinates G_x and G_y.
"""

# secp256k1 constants for elliptic curve cryptography

# The prime modulus of the field
P: int = 2**256 - 2**32 - 977

# The order of the curve
Q: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# X-coordinate of the generator point G
G_x: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

# Y-coordinate of the generator point G
G_y: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
