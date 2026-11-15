"""Draws keyed by what they are about, so every design sees the same luck."""

import hashlib

import numpy as np


def u(*key: object) -> float:
    h = hashlib.blake2b("|".join(map(str, key)).encode(), digest_size=8).digest()
    return int.from_bytes(h, "big") / 2**64


def pick(seq, *key: object):
    return seq[int(u(*key) * len(seq)) % len(seq)]


def rng(*key: object) -> np.random.Generator:
    return np.random.default_rng(int(u(*key) * 2**63))
