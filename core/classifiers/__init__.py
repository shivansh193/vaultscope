"""Stage 4a + 4b - Classifiers (P2, Block A / @shivansh193).

Stage 4a  Protocol/Crypto Classifier - Random Forest fallback for sessions
          where deterministic IKE parsing is incomplete.
Stage 4b  Traffic-Type Classifier - the core ML component. Given a Stage 3
          flow feature vector, predicts the traffic type inside the tunnel
          (VoIP | Video | Web | Email | ICMP | Chat).

See spec Section 4 "Stage 4a" / "Stage 4b".
"""
