"""Stage 2 - IKE Parser (P2, Block A / @shivansh193).

Reconstructs the full IKEv1/IKEv2 handshake from a raw packet stream and
extracts every negotiated cryptographic parameter into a VPNSession object.

See spec Section 4 "Stage 2 - IKE Parser" and Section 5.1 for the output schema.

Public API
----------
    parse_ikev2(source)            -> VPNSession        (primary IKEv2 SA)
    parse_ikev2_sessions(source)   -> list[VPNSession]
    parse_ikev1(source)            -> VPNSession        (primary IKEv1 phase-1 SA)
    parse_ikev1_sessions(source)   -> list[VPNSession]
    VPNSession                     dataclass, spec Section 5.1 `ike` sub-object

``source`` is a pcap path, raw IKE bytes, or an iterable of either.
IKEv1 Quick Mode / PFS extraction lands in P2-T3.
"""

from ._wire import IkeMessage, WireFormatError, decode_message
from .ikev1 import NoIKEv1Error, exchange_mode_name, parse_ikev1, parse_ikev1_sessions
from .ikev2 import NoIKEv2Error, iter_ike_messages, parse_ikev2, parse_ikev2_sessions
from .models import VPNSession

__all__ = [
    "parse_ikev2",
    "parse_ikev2_sessions",
    "parse_ikev1",
    "parse_ikev1_sessions",
    "exchange_mode_name",
    "iter_ike_messages",
    "VPNSession",
    "IkeMessage",
    "decode_message",
    "WireFormatError",
    "NoIKEv2Error",
    "NoIKEv1Error",
]
