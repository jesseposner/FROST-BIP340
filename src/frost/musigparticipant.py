from hashlib import sha256
from typing import Optional, Tuple
import secrets
from .point import Point, G
from .constants import Q


class MusigParticipant:
    def __init__(self, index: int, participants: int):
        self.index = index
        self.participants = participants
        self.private_key: Optional[int] = None
        self.public_key: Optional[Point] = None
        self.nonce: Optional[int] = None
        self.nonce_commitment: Optional[Point] = None
        self.nonce_hash: Optional[str] = None
        self.aggregate_public_key: Optional[Point] = None
        self.aggregate_nonce_commitment: Optional[Point] = None

    def generate_private_key(self) -> None:
        if self.private_key is not None:
            raise ValueError("Private key already set")

        self.private_key = secrets.randbits(256) % Q

    def generate_public_key(self) -> None:
        if self.private_key is None:
            raise ValueError("Private key not set")
        if self.public_key is not None:
            raise ValueError("Public key already set")

        self.public_key = self.private_key * G

    def generate_aggregate_public_key(
        self, other_public_keys: Tuple[Point, ...]
    ) -> None:
        if self.private_key is None:
            raise ValueError("Private key not set")
        if self.public_key is None:
            raise ValueError("Public key not set")

        serialized_key_list = [key.sec_serialize() for key in other_public_keys]
        serialized_public_key = self.public_key.sec_serialize()
        serialized_key_list.append(serialized_public_key)
        sorted_keys = b"".join(sorted(serialized_key_list))
        tweaked_keys = tuple(
            self.generate_keyagg_coeff(serialized_public_key, sorted_keys)
            * Point.sec_deserialize(key.hex())
            for key in serialized_key_list
        )
        self.aggregate_public_key = sum(tweaked_keys, Point(0, 0))

    def generate_keyagg_coeff(self, key: bytes, sorted_keys: bytes) -> int:
        key_agg_hash = sha256()
        key_agg_hash.update(sorted_keys)
        key_agg_hash.update(key)
        return int.from_bytes(key_agg_hash.digest(), "big") % Q

    def generate_nonce(self) -> None:
        if self.nonce is not None:
            raise ValueError("Nonce already set")
        if self.nonce_commitment is not None:
            raise ValueError("Nonce commitment already set")

        self.nonce = secrets.randbits(256) % Q
        self.nonce_commitment = self.nonce * G
        self.nonce_hash = sha256(self.nonce_commitment.sec_serialize()).hexdigest()

    def generate_aggregate_nonce_commitment(
        self, nonce_commitments: Tuple[Point, ...]
    ) -> Point:
        return sum(nonce_commitments, Point(0, 0))

    def signature(
        self, partial_signatures: Tuple[int, ...], aggregate_nonce_commitment: Point
    ) -> str:
        z = (sum(partial_signatures) % Q).to_bytes(32, "big")

        return (aggregate_nonce_commitment.xonly_serialize() + z).hex()
