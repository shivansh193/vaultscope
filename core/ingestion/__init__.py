"""Stage 1 - Ingestion Engine (P1, Block A / @shivansh193).

Accept a pcap file or live NIC interface and produce per-session packet
streams bucketed by IKE session identifiers (pyshark wrapper + scapy
fallback + session bucketing).

See spec Section 4 "Stage 1 - Ingestion Engine".
"""
