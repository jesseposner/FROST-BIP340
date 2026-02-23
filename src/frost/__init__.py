"""
FROST-BIP340: Educational reference implementation of FROST threshold
Schnorr signatures for secp256k1/BIP340.

Core types:
- Participant: State container and protocol orchestrator
- Aggregator: Signature aggregation and verification
- Point: secp256k1 curve point
- Scalar: Scalar field element (Z_Q)

Protocol modules (for direct use or learning):
- frost.keygen:     Distributed Key Generation
- frost.signing:    FROST threshold signing
- frost.repair:     Share repair and enrollment
- frost.threshold:  Threshold increase and decrease
- frost.lagrange:   Lagrange interpolation
- frost.polynomial: Polynomial operations
"""

from .aggregator import Aggregator as Aggregator
from .constants import CURVE_ORDER as CURVE_ORDER
from .constants import FIELD_ORDER as FIELD_ORDER
from .constants import P as P
from .constants import Q as Q
from .matrix import Matrix as Matrix
from .participant import Participant as Participant
from .point import G as G
from .point import Point as Point
from .scalar import Scalar as Scalar
