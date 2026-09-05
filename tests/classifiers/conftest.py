"""Make the Stage 2 synthetic-message builders importable for Stage 4a tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ike_parser"))
