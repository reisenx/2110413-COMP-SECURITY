#!/usr/bin/env python3
"""Count letter frequencies in the Homework 4 substitution ciphertext."""

from collections import Counter

CIPHERTEXT = (
    "PRCSOFQX FP QDR AFOPQ CZSPR LA JFPALOQSKR. "
    "QDFP FP ZK LIU BROJZK MOLTROE."
)


def main() -> None:
    letters = [c for c in CIPHERTEXT.upper() if c.isalpha()]
    counts = Counter(letters)
    ranked = counts.most_common()

    print("ciphertext:")
    print(CIPHERTEXT)
    print()
    print(f"letter_count={len(letters)}")
    print(f"unique_letters={len(counts)}")
    print()
    print("rank letter count")
    for i, (letter, count) in enumerate(ranked, start=1):
        print(f"{i:>4} {letter}      {count}")
    print()
    print("top_three:")
    print("1. P (7)")
    print("2-4. R, O, F (6 each)")


if __name__ == "__main__":
    main()
