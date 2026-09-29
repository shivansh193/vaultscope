"""Stage 1 - Ingestion Engine (P1).

Accept a pcap / pcapng file and produce per-session packet streams bucketed by
IKE SA identifier: ``(SPI_i, SPI_r)`` for IKEv2, ``(cookie_i, cookie_r)`` for
IKEv1. Each session's ESP/AH data-plane packets are kept alongside it for
Stage 3.

    from core.ingestion import ingest
    result = ingest("capture.pcap")
    result.summary()          # {session_count, has_esp, incomplete_sessions, ...}
    result.to_vpn_sessions()  # Stage 1 + Stage 2 off the same read

See product spec Section 4 "Stage 1 - Ingestion Engine" and LLD Section 3.2.
"""

from .engine import IngestResult, RawSession, bucket, ingest

__all__ = ["ingest", "bucket", "IngestResult", "RawSession"]
