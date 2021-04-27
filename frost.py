# Copyright (c) 2021 Jesse Posner
# Distributed under the MIT software license, see the accompanying file LICENSE
# or http://www.opensource.org/licenses/mit-license.php.
#
# This code is currently a work in progress. It's not secure nor stable.  IT IS
# EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!
#
# This module implements Flexible Round-Optimized Schnorr Threshold Signatures
# (FROST) by Chelsea Komlo and Ian Goldberg
# (https://crysp.uwaterloo.ca/software/frost/).

"""Python FROST adaptor signatures implementation."""

import secrets

class FROST:
    class secp256k1:
        P = 2**256 - 2**32 - 977
        Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        G_x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        G_y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

        @classmethod
        def G(cls):
            return FROST.Point(cls.G_x, cls.G_y)

    class Participant:
        """Class representing a FROST participant."""

        CONTEXT = b'FROST-BIP340'

        def __init__(self, index, threshold, coefficients=[], coefficient_commitments=[], proof_of_knowledge=[]):
            self.index = index
            self.threshold = threshold
            self.coefficients = coefficients
            self.coefficient_commitments = coefficient_commitments
            self.proof_of_knowledge = proof_of_knowledge

        def init_keygen(self):
            Q = FROST.secp256k1.Q
            G = FROST.secp256k1.G()
            # 1. Generate polynomial with random coefficients, and with degree
            # equal to the threshold minus one.
            #
            # f(x) = ∑ a_i_j * x^j, 0 ≤ j ≤ t - 1
            self.coefficients = [secrets.randbits(256) % Q for _ in range(self.threshold)]
            # 2. Compute proof of knowledge of secret a_i_0.
            #
            # k ⭠ Z_q
            nonce = secrets.randbits(256) % Q
            # R_i = g^k
            nonce_commitment = nonce * G
            # i
            index_bytes = int.to_bytes(self.index, 1, 'big')
            # 𝚽
            context_bytes = self.CONTEXT
            # g^a_i_0
            secret = self.coefficients[0]
            secret_commitment = secret * G
            secret_commitment_bytes = bytes.fromhex(secret_commitment.sec_serialize())
            # R_i
            nonce_commitment_bytes = bytes.fromhex(nonce_commitment.sec_serialize())
            # c_i = H(i, 𝚽, g^a_i_0, R_i)
            challenge_input = index_bytes + context_bytes + secret_commitment_bytes + nonce_commitment_bytes
            challenge_hash_bytes = sha256(challenge_input).digest()
            challenge_hash_int = int.from_bytes(challenge_hash_bytes, 'big')
            # μ_i = k + a_i_0 * c_i
            s = (nonce + secret * challenge_hash_int) % Q
            # σ_i = (R_i, μ_i)
            self.proof_of_knowledge = [nonce_commitment, s]
            # 3. Compute coefficient commitments.
            #
            # C_i = ⟨𝜙_i_0, ..., 𝜙_i_(t-1)⟩
            # 𝜙_i_j = g^a_i_j, 0 ≤ j ≤ t -1
            self.coefficient_commitments = [coefficient * G for coefficient in self.coefficients]

    class Point:
        """Class representing an elliptic curve point."""

        def __init__(self, x=float('inf'), y=float('inf')):
            self.x = x
            self.y = y

        @classmethod
        def sec_deserialize(cls, hex_public_key):
            P = FROST.secp256k1.P
            hex_bytes = bytes.fromhex(hex_public_key)
            is_even = hex_bytes[0] == 2
            x_bytes = hex_bytes[1:]
            x = int.from_bytes(x_bytes, 'big')
            y_squared = (pow(x, 3, P) + 7) % P
            y = pow(y_squared, (P + 1) // 4, P)
            if y % 2 == 0:
                even_y = y
                odd_y = (P - y) % P
            else:
                even_y = (P - y) % P
                odd_y = y
            y = even_y if is_even else odd_y

            return cls(x, y)

        def sec_serialize(self):
            prefix = '02' if self.y % 2 == 0 else '03'

            return prefix + format(self.x, 'x')

        # point at infinity
        def is_zero(self):
            return self.x == float('inf') or self.y == float('inf')

        def __eq__(self, other):
            return self.x == other.x and self.y == other.y

        def __ne__(self, other):
            return not self == other

        def __neg__(self):
            if self.is_zero():
                return self

            return self.__class__(self.x, self.P - self.y)

        def dbl(self):
            x = self.x
            y = self.y
            P = FROST.secp256k1.P
            s = (3 * x * x * pow(2 * y, P - 2, P)) % P
            sum_x = (s * s - 2 * x) % P
            sum_y = (s * (x - sum_x) - y) % P

            return self.__class__(sum_x, sum_y)

        def __add__(self, other):
            P = FROST.secp256k1.P

            if self == other:
                return self.dbl()
            if self.is_zero():
                return other
            if other.is_zero():
                return self
            if self.x == other.x and self.y != other.y:
                return self.__class__()
            s = ((other.y - self.y) * pow(other.x - self.x, P - 2, P)) % P
            sum_x = (s * s - self.x - other.x) % P
            sum_y = (s * (self.x - sum_x) - self.y) % P

            return self.__class__(sum_x, sum_y)

        def __rmul__(self, scalar):
            p = self
            r = self.__class__()
            i = 1

            while i <= scalar:
                if i & scalar:
                    r = r + p
                p = p.dbl()
                i <<= 1

            return r

        def __str__(self):
            if self.is_zero():
                return '0'
            return 'X: 0x{:x}\nY: 0x{:x}'.format(self.x, self.y)

        def __repr__(self) -> str:
            return self.__str__()
