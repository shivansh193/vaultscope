"""Stage 2 - IKE Parser (P2, Block A / @shivansh193).

Reconstructs the full IKEv1/IKEv2 handshake from a raw packet stream and
extracts every negotiated cryptographic parameter into a VPNSession object.

See spec Section 4 "Stage 2 - IKE Parser" and Section 5.1 for the output schema.
"""
