"""
This package provides cryptographic functionalities for
implementing the FROST signature scheme.

Modules:
- point: Defines the Point class for handling points on
  an elliptic curve.
- participant: Contains the Participant class for
  managing participants in the FROST scheme.
- aggregator: Implements the Aggregator class to
  coordinate the aggregation of cryptographic elements.
- constants: Holds cryptographic constants like P, Q,
and G, crucial for elliptic curve operations.

The package supports operations such as point
arithmetic, nonce generation, share aggregation, and
signature generation, all within the context of
threshold cryptography.
"""

from .point import Point, P, Q, G
from .participant import Participant
from .aggregator import Aggregator
