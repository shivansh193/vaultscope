"""Stage 1 - Ingestion Engine (P1, Block A / @shivansh193).

Accept a pcap / pcapng file (or, via the pyshark backend, a live interface) and
produce per-session packet streams bucketed by IKE SA identifier:
``(SPI_i, SPI_r)`` for IKEv2, ``(cookie_i, cookie_r)`` for IKEv1. The ESP/AH
data-plane packets are kept alongside each session for Stage 3.

    from core.ingestion import ingest
    result = ingest("capture.pcap")                    # scapy backend (default)
    result = ingest("capture.pcap", prefer="pyshark")  # structured, falls back
    result.summary()                                   # {session_count, has_esp, ...}
    result.to_vpn_sessions()                            # Stage 1 + Stage 2 in one read

See product spec Section 4 "Stage 1 - Ingestion Engine" and LLD Section 3.2.
"""

from .engine import IngestResult, RawSession, ingest

__all__ = ["ingest", "IngestResult", "RawSession"]
