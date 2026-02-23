"""
Copyright (c) 2021-2024 Jesse Posner

Distributed under the MIT software license, see the accompanying file LICENSE
or http://www.opensource.org/licenses/mit-license.php.

This code is currently a work in progress. It's not secure nor stable.  IT IS
EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

This package provides cryptographic functionalities for implementing the FROST
signature scheme.

Modules:
- point: Defines the Point class for handling points on an elliptic curve.
- participant: Contains the Participant class for managing participants in the
  FROST scheme.
- aggregator: Implements the Aggregator class to coordinate the aggregation of
  cryptographic elements.
- constants: Holds cryptographic constants like P, Q, and G, crucial for
  elliptic curve operations.

The package supports operations such as point arithmetic, nonce generation,
share aggregation, and signature generation, all within the context of
threshold cryptography.
"""

from .aggregator import Aggregator as Aggregator
from .matrix import Matrix as Matrix
from .participant import Participant as Participant
from .point import G as G
from .point import P as P
from .point import Point as Point
from .point import Q as Q
from .scalar import Scalar as Scalar
