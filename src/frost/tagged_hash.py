"""BIP340 tagged hash utility.

Tagged hashes ensure that hashes used in different contexts (challenges,
nonces, tweaks) cannot collide, even if their inputs are identical. This
is a domain separation technique defined in BIP340.

    tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
"""

from hashlib import sha256


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """Compute a BIP340 tagged hash.

    Parameters:
    tag: Domain separator string (e.g. "BIP0340/challenge").
    msg: The message bytes to hash.

    Returns:
    The 32-byte SHA256 digest.
    """
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + msg).digest()
