#!/usr/bin/env python3
"""Run Homework 4 experiments: image ECB/CBC demo and OpenSSL speed tests."""

from __future__ import annotations

import os
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HW_ROOT = ROOT.parent
DOCS = HW_ROOT / "docs"
IMAGES = DOCS / "images"
SOURCE = IMAGES / "source.jpg"
OUT = ROOT / "output"
OPENSSL = Path("/opt/homebrew/opt/openssl@3/bin/openssl")
MAGICK = shutil.which("magick") or "/opt/homebrew/bin/magick"

# Documented demonstration material only. These are not production secrets.
AES_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
AES_IV = "0102030405060708090a0b0c0d0e0f10"
SPEED_SECONDS = "3"
SPEED_REPEATS = 3


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


def split_pbm(path: Path) -> tuple[bytes, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"P4"):
        raise SystemExit(f"{path} is not a binary PBM (P4) file")
    offset = 0
    lines_kept = 0
    header_parts = []
    while offset < len(data) and lines_kept < 2:
        nl = data.find(b"\n", offset)
        if nl < 0:
            raise SystemExit(f"truncated PBM header in {path}")
        line = data[offset : nl + 1]
        offset = nl + 1
        if line.startswith(b"#"):
            continue
        header_parts.append(line)
        lines_kept += 1
    header = b"".join(header_parts)
    body = data[offset:]
    return header, body


def pad16(body: bytes) -> tuple[bytes, int]:
    pad = (16 - (len(body) % 16)) % 16
    if pad:
        body = body + (b"\x00" * pad)
    return body, pad


def openssl_enc(cipher: str, src: Path, dst: Path, iv: str | None = None) -> None:
    cmd = [
        str(OPENSSL),
        "enc",
        f"-{cipher}",
        "-in",
        str(src),
        "-out",
        str(dst),
        "-nosalt",
        "-nopad",
        "-K",
        AES_KEY,
    ]
    if iv is not None:
        cmd.extend(["-iv", iv])
    run(cmd)


def write_pbm(path: Path, header: bytes, body: bytes, unpad: int) -> None:
    if unpad:
        body = body[:-unpad]
    path.write_bytes(header + body)


def image_experiment() -> dict:
    if not SOURCE.exists():
        raise SystemExit(f"missing source image: {SOURCE}")
    work = OUT / "image"
    work.mkdir(parents=True, exist_ok=True)

    org_pbm = work / "org.pbm"
    run(
        [
            MAGICK,
            str(SOURCE),
            "-resize",
            "2000x2000!",
            "-colorspace",
            "Gray",
            "-threshold",
            "50%",
            "pbm:" + str(org_pbm),
        ]
    )

    header, body = split_pbm(org_pbm)
    body, pad = pad16(body)
    org_x = work / "org.x"
    org_x.write_bytes(body)

    enc_ecb = work / "enc-ecb.x"
    enc_cbc = work / "enc-cbc.x"
    openssl_enc("aes-256-ecb", org_x, enc_ecb)
    openssl_enc("aes-256-cbc", org_x, enc_cbc, iv=AES_IV)

    orig_view = IMAGES / "original.png"
    ecb_pbm = work / "enc-ecb.pbm"
    cbc_pbm = work / "enc-cbc.pbm"
    write_pbm(ecb_pbm, header, enc_ecb.read_bytes(), pad)
    write_pbm(cbc_pbm, header, enc_cbc.read_bytes(), pad)

    run([MAGICK, str(org_pbm), str(orig_view)])
    run([MAGICK, str(ecb_pbm), str(IMAGES / "aes256-ecb.png")])
    run([MAGICK, str(cbc_pbm), str(IMAGES / "aes256-cbc.png")])
    run(
        [
            MAGICK,
            str(orig_view),
            str(IMAGES / "aes256-ecb.png"),
            str(IMAGES / "aes256-cbc.png"),
            "+append",
            "-resize",
            "x800",
            str(IMAGES / "mode-comparison.png"),
        ]
    )

    identify = subprocess.check_output([MAGICK, "identify", str(org_pbm)], text=True)
    return {
        "identify": identify.strip(),
        "header": header.decode("ascii"),
        "body_bytes": len(body) - pad,
        "padded_bytes": len(body),
        "pad": pad,
    }


SPEED_LINE = re.compile(
    r"^(sha1|rc4|blowfish)\s+([0-9.]+)k\s+([0-9.]+)k\s+([0-9.]+)k\s+"
    r"([0-9.]+)k\s+([0-9.]+)k\s+([0-9.]+)k\s*$"
)
DSA_LINE = re.compile(
    r"^dsa\s+(\d+)\s+bits\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)\s+([0-9.]+)\s*$"
)


def speed_once(alg: str, extra: list[str], dest: Path) -> str:
    cmd = [str(OPENSSL), "speed", "-seconds", SPEED_SECONDS, *extra, alg]
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, check=True, text=True)
    return dest.read_text()


def parse_sym(text: str, name: str) -> dict[str, float]:
    for line in text.splitlines():
        m = SPEED_LINE.match(line.strip())
        if m and m.group(1) == name:
            sizes = [16, 64, 256, 1024, 8192, 16384]
            return {str(sz): float(val) for sz, val in zip(sizes, m.groups()[1:])}
    raise SystemExit(f"could not parse {name} speed output:\n{text}")


def parse_dsa(text: str) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        m = DSA_LINE.match(line.strip())
        if m:
            bits = m.group(1)
            out[bits] = {
                "sign_s": float(m.group(2)),
                "verify_s": float(m.group(3)),
                "sign_per_s": float(m.group(4)),
                "verify_per_s": float(m.group(5)),
            }
    if not out:
        raise SystemExit(f"could not parse DSA speed output:\n{text}")
    return out


def median_maps(maps: list[dict[str, float]]) -> dict[str, float]:
    keys = maps[0].keys()
    return {k: statistics.median(m[k] for m in maps) for k in keys}


def speed_experiments() -> dict:
    speed_dir = OUT / "speed"
    speed_dir.mkdir(parents=True, exist_ok=True)
    legacy = ["-provider", "legacy", "-provider", "default"]

    sha_runs = []
    rc4_runs = []
    bf_runs = []
    dsa_runs = []
    for i in range(1, SPEED_REPEATS + 1):
        sha_text = speed_once("sha1", [], speed_dir / f"sha1-{i}.txt")
        rc4_text = speed_once("rc4", legacy, speed_dir / f"rc4-{i}.txt")
        bf_text = speed_once("blowfish", legacy, speed_dir / f"blowfish-{i}.txt")
        dsa_text = speed_once("dsa", [], speed_dir / f"dsa-{i}.txt")
        sha_runs.append(parse_sym(sha_text, "sha1"))
        rc4_runs.append(parse_sym(rc4_text, "rc4"))
        bf_runs.append(parse_sym(bf_text, "blowfish"))
        dsa_runs.append(parse_dsa(dsa_text))

    dsa_bits = sorted(dsa_runs[0].keys(), key=int)
    dsa_med = {}
    for bits in dsa_bits:
        dsa_med[bits] = median_maps([run[bits] for run in dsa_runs])

    return {
        "sha1": median_maps(sha_runs),
        "rc4": median_maps(rc4_runs),
        "blowfish": median_maps(bf_runs),
        "dsa": dsa_med,
        "openssl": subprocess.check_output([str(OPENSSL), "version"], text=True).strip(),
        "imagemagick": subprocess.check_output([MAGICK, "-version"], text=True).splitlines()[0],
        "python": sys.version.split()[0],
        "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip(),
    }


def write_summary(image_info: dict, speed_info: dict) -> None:
    lines = []
    lines.append(f"openssl={speed_info['openssl']}")
    lines.append(f"imagemagick={speed_info['imagemagick']}")
    lines.append(f"python={speed_info['python']}")
    lines.append(f"cpu={speed_info['cpu']}")
    lines.append(f"pbm_identify={image_info['identify']}")
    lines.append("pbm_header=")
    lines.append(image_info["header"].rstrip("\n"))
    lines.append(f"body_bytes={image_info['body_bytes']}")
    lines.append(f"padded_bytes={image_info['padded_bytes']}")
    lines.append(f"pad={image_info['pad']}")
    lines.append(f"aes_key={AES_KEY}")
    lines.append(f"aes_iv={AES_IV}")
    for name in ("sha1", "rc4", "blowfish"):
        row = speed_info[name]
        vals = " ".join(f"{k}={row[k]:.2f}kB/s" for k in ["16", "64", "256", "1024", "8192", "16384"])
        lines.append(f"{name} {vals}")
    for bits, row in speed_info["dsa"].items():
        lines.append(
            f"dsa{bits} sign_s={row['sign_s']:.6f} verify_s={row['verify_s']:.6f} "
            f"sign_per_s={row['sign_per_s']:.1f} verify_per_s={row['verify_per_s']:.1f}"
        )
    (OUT / "summary.txt").write_text("\n".join(lines) + "\n")
    print((OUT / "summary.txt").read_text())


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    freq = subprocess.check_output([sys.executable, str(ROOT / "frequency_analysis.py")], text=True)
    (OUT / "frequency.txt").write_text(freq)
    print(freq)
    sample = subprocess.check_output(
        [sys.executable, str(ROOT / "caesar_bruteforce.py")],
        text=True,
    )
    (OUT / "caesar-sample.txt").write_text(sample)
    homework_ct = (
        "PRCSOFQX FP QDR AFOPQ CZSPR LA JFPALOQSKR. QDFP FP ZK LIU BROJZK MOLTROE."
    )
    not_caesar = subprocess.check_output(
        [sys.executable, str(ROOT / "caesar_bruteforce.py"), homework_ct],
        text=True,
    )
    (OUT / "caesar-homework-ct.txt").write_text(not_caesar)
    image_info = image_experiment()
    speed_info = speed_experiments()
    write_summary(image_info, speed_info)


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
