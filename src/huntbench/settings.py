"""Settings the platform reads. The world's files are read only by the evaluation and the tests."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
DETECTIONS = ROOT / "detections"


def load(name: str) -> dict:
    return tomllib.loads((CONFIG / f"{name}.toml").read_text())
