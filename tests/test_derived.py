import secrets

from frost import Aggregator, G, Q


def test_derive_coefficient_commitments(keygen_group):
    p1, p2, p3 = keygen_group

    coefficient_commitments = p1.group_commitments
    assert p1.public_verification_share() == (
        coefficient_commitments[0] + (1 * coefficient_commitments[1])
    )
    assert p2.public_verification_share() == (
        coefficient_commitments[0] + (2 * coefficient_commitments[1])
    )
    assert p3.public_verification_share() == (
        coefficient_commitments[0] + (3 * coefficient_commitments[1])
    )

    derived_coefficient_commitments = p1.derive_coefficient_commitments(
        (p1.public_verification_share(), p2.public_verification_share()), (1, 2)
    )
    assert coefficient_commitments == derived_coefficient_commitments


def test_derive_shared_secret(keygen_group):
    p1, p2, _p3 = keygen_group

    alice_private_key = secrets.randbits(256) % Q
    alice_public_key = alice_private_key * G

    shared_secret_share_1 = p1.derive_shared_secret_share(alice_public_key, (2,))
    shared_secret_share_2 = p2.derive_shared_secret_share(alice_public_key, (1,))

    shared_secret = Aggregator.derive_shared_secret((shared_secret_share_1, shared_secret_share_2))

    assert shared_secret == alice_private_key * p1.public_key
