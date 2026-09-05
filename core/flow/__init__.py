"""Stage 3 - ESP/AH Flow Feature Extractor (owner: P2).

Since the ESP payload is encrypted, traffic characteristics are inferred from
metadata only. Produces a 12-feature vector per flow for the Stage 4b
traffic-type classifier.

See spec Section 4 "Stage 3 - ESP/AH Flow Feature Extractor".
"""
