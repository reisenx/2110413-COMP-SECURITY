#!/usr/bin/env python3
"""Brute-force a Caesar cipher by trying all 26 shifts.

The scorer combines English letter-frequency chi-squared with a small
list of common words. Lower chi-squared is better; word hits break ties
and make the ranking easier to read.
"""

from __future__ import annotations

import argparse
import math
import string
from dataclasses import dataclass

ENGLISH_FREQ = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}

COMMON_WORDS = {
    "A",
    "AN",
    "AND",
    "THE",
    "IS",
    "OF",
    "TO",
    "IN",
    "THIS",
    "THAT",
    "FOR",
    "WITH",
    "ON",
    "AS",
    "ARE",
    "WAS",
    "BE",
    "IT",
    "SECURITY",
    "FIRST",
    "CAUSE",
    "MISFORTUNE",
    "GERMAN",
    "PROVERB",
    "OLD",
}

DEFAULT_SAMPLE = "VHFXULWB LV WKH ILUVW FDXVH RI PLVIRUWXQH."


@dataclass(frozen=True)
class Candidate:
    shift: int
    plaintext: str
    chi_squared: float
    word_hits: int

    @property
    def score_key(self) -> tuple:
        return (-self.word_hits, self.chi_squared, self.shift)


def caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr(base + (ord(ch) - base - shift) % 26))
        else:
            out.append(ch)
    return "".join(out)


def chi_squared(text: str) -> float:
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)
    if n == 0:
        return math.inf
    counts = {c: 0 for c in string.ascii_uppercase}
    for c in letters:
        counts[c] += 1
    score = 0.0
    for letter, p in ENGLISH_FREQ.items():
        expected = p * n
        observed = counts[letter]
        score += (observed - expected) ** 2 / expected
    return score


def word_hits(text: str) -> int:
    tokens = "".join(ch if ch.isalpha() else " " for ch in text.upper()).split()
    return sum(1 for tok in tokens if tok in COMMON_WORDS)


def crack(ciphertext: str) -> list[Candidate]:
    results = []
    for shift in range(26):
        plain = caesar_shift(ciphertext, shift)
        results.append(
            Candidate(
                shift=shift,
                plaintext=plain,
                chi_squared=chi_squared(plain),
                word_hits=word_hits(plain),
            )
        )
    return sorted(results, key=lambda c: c.score_key)


def main() -> None:
    parser = argparse.ArgumentParser(description="Brute-force a Caesar cipher.")
    parser.add_argument(
        "ciphertext",
        nargs="?",
        default=DEFAULT_SAMPLE,
        help="Ciphertext to attack. Default is a Caesar sample, not the homework substitution cipher.",
    )
    args = parser.parse_args()

    ranked = crack(args.ciphertext)
    print("ciphertext:")
    print(args.ciphertext)
    print()
    print("All 26 shifts, best first (more dictionary hits, then lower chi-squared):")
    print()
    for i, cand in enumerate(ranked, start=1):
        marker = "  <-- best" if i == 1 else ""
        print(
            f"{i:>2}. shift={cand.shift:2d}  chi2={cand.chi_squared:8.2f}  "
            f"words={cand.word_hits:2d}{marker}"
        )
        print(f"    {cand.plaintext}")


if __name__ == "__main__":
    main()
