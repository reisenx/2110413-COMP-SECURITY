#!/usr/bin/env python3
import sys

WORDS = {"A", "AN", "THE", "IS", "OF", "TO", "IN", "THIS",
         "SECURITY", "FIRST", "CAUSE", "MISFORTUNE"}
SAMPLE = "VHFXULWB LV WKH ILUVW FDXVH RI PLVIRUWXQH."


def decrypt(text, shift):
    return "".join(
        chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        if c.isalpha() else c
        for c in text.upper()
    )


def score(text):
    words = "".join(c if c.isalpha() else " " for c in text).split()
    return sum(word in WORDS for word in words)


ciphertext = " ".join(sys.argv[1:]) or SAMPLE
results = []

for shift in range(26):
    plaintext = decrypt(ciphertext, shift)
    results.append((score(plaintext), shift, plaintext))

for points, shift, plaintext in sorted(
        results, key=lambda row: (-row[0], row[1])):
    print(f"shift={shift:2} score={points}: {plaintext}")
