from hashlib import sha256
from typing import Optional, Tuple, List
import secrets
from .point import Point, G
from .constants import Q
from .aggregator import Aggregator


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
        self.keyagg_coeff: Optional[int] = None

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

        key_list = list(other_public_keys)
        key_list.append(self.public_key)
        tweaked_keys = tuple(
            self.generate_keyagg_coeff(key, key_list) * key for key in key_list
        )
        self.aggregate_public_key = sum(tweaked_keys, Point())
        self.keyagg_coeff = self.generate_keyagg_coeff(self.public_key, key_list)

    def generate_keyagg_coeff(self, key: Point, keys: List[Point]) -> int:
        serialized_key_list = [key.sec_serialize() for key in keys]
        sorted_keys = b"".join(sorted(serialized_key_list))
        key_agg_hash = sha256()
        key_agg_hash.update(sorted_keys)
        key_agg_hash.update(key.sec_serialize())
        return int.from_bytes(key_agg_hash.digest(), "big") % Q

    def generate_nonce(self) -> None:
        if self.nonce is not None:
            raise ValueError("Nonce already set")
        if self.nonce_commitment is not None:
            raise ValueError("Nonce commitment already set")

        self.nonce = secrets.randbits(256) % Q
        self.nonce_commitment = self.nonce * G
        self.nonce_hash = sha256(self.nonce_commitment.sec_serialize()).hexdigest()

    def verify_nonce_commitment(self, nonce_commitment: Point, nonce_hash: str) -> bool:
        return nonce_hash == sha256(nonce_commitment.sec_serialize()).hexdigest()

    def generate_aggregate_nonce_commitment(
        self, other_nonce_commitments: Tuple[Point, ...]
    ) -> None:
        if self.nonce_commitment is None:
            raise ValueError("Nonce commitment not set")

        self.aggregate_nonce_commitment = sum(
            other_nonce_commitments, self.nonce_commitment
        )

    def partial_sign(self, message: bytes) -> int:
        if not self.aggregate_nonce_commitment:
            raise ValueError("Aggregate nonce commitment not set")
        if not self.aggregate_public_key:
            raise ValueError("Aggregate public key not set")
        if not self.aggregate_public_key.y:
            raise ValueError("Aggregate public key not set")
        if not self.aggregate_nonce_commitment.y:
            raise ValueError("Aggregate nonce commitment not set")
        if not self.nonce:
            raise ValueError("Nonce not set")
        if not self.private_key:
            raise ValueError("Private key not set")
        if not self.keyagg_coeff:
            raise ValueError("Key aggregation coefficient not set")

        challenge_hash = Aggregator.challenge_hash(
            self.aggregate_nonce_commitment, self.aggregate_public_key, message
        )
        nonce = self.nonce
        private_key = self.private_key
        if self.aggregate_nonce_commitment.y % 2 != 0:
            nonce = Q - nonce
        if self.aggregate_public_key.y % 2 != 0:
            private_key = Q - private_key

        return (nonce + (challenge_hash * private_key * self.keyagg_coeff)) % Q

    def signature(self, partial_signatures: Tuple[int, ...]) -> str:
        if not self.aggregate_nonce_commitment:
            raise ValueError("Aggregate nonce commitment not set")

        z = (sum(partial_signatures) % Q).to_bytes(32, "big")

        return (self.aggregate_nonce_commitment.xonly_serialize() + z).hex()
