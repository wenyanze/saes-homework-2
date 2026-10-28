"""Command-line interface for reproducible S-AES demonstrations."""

from __future__ import annotations

import argparse
import sys

from saes import (
    ascii_decrypt,
    ascii_encrypt,
    bytes_to_display,
    cbc_decrypt,
    cbc_encrypt,
    decrypt_block,
    double_decrypt,
    double_encrypt,
    encrypt_block,
    expand_key,
    format_hex,
    meet_in_the_middle,
    parse_hex,
    tamper_ciphertext,
    triple_decrypt,
    triple_encrypt,
)


def _hex_bytes(text: str) -> bytes:
    normalized = text.strip().replace(" ", "").replace("_", "")
    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]
    if not normalized or len(normalized) % 2 or any(character not in "0123456789abcdefABCDEF" for character in normalized):
        raise ValueError("byte string must contain an even number of hexadecimal digits")
    return bytes.fromhex(normalized)


def _parse_pair(text: str) -> tuple[int, int]:
    for separator in (":", ",", " "):
        if separator in text:
            left, right = text.split(separator, 1)
            return parse_hex(left, 16, "plaintext"), parse_hex(right, 16, "ciphertext")
    raise ValueError("a pair must have the form PLAINTEXT:CIPHERTEXT")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="S-AES reference implementation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    block = subparsers.add_parser("block", help="encrypt or decrypt one 16-bit block")
    block.add_argument("operation", choices=("encrypt", "decrypt"))
    block.add_argument("data", help="16-bit hexadecimal plaintext or ciphertext")
    block.add_argument("key", help="16-bit hexadecimal key")

    text = subparsers.add_parser("text", help="encrypt/decrypt an ASCII string")
    text.add_argument("operation", choices=("encrypt", "decrypt"))
    text.add_argument("data", help="ASCII text for encrypt, hexadecimal bytes for decrypt")
    text.add_argument("key", help="16-bit hexadecimal key")

    multi = subparsers.add_parser("multi", help="double or triple encryption")
    multi.add_argument("operation", choices=("encrypt", "decrypt"))
    multi.add_argument("mode", choices=("double", "eee", "ede", "ede2"))
    multi.add_argument("data", help="16-bit hexadecimal block")
    multi.add_argument("key1", help="first 16-bit key")
    multi.add_argument("key2", help="second 16-bit key")
    multi.add_argument("key3", nargs="?", help="third 16-bit key for eee/ede")

    mitm = subparsers.add_parser("mitm", help="meet-in-the-middle attack on double encryption")
    mitm.add_argument("--pair", action="append", required=True, help="known pair PLAINTEXT:CIPHERTEXT; repeat for more pairs")
    mitm.add_argument("--max-results", type=int, default=None)

    cbc = subparsers.add_parser("cbc", help="CBC mode with a 16-bit IV")
    cbc.add_argument("operation", choices=("encrypt", "decrypt", "tamper"))
    cbc.add_argument("data", help="ASCII text for encrypt, hexadecimal bytes otherwise")
    cbc.add_argument("key", help="16-bit hexadecimal key")
    cbc.add_argument("iv", help="16-bit hexadecimal initial vector")
    cbc.add_argument("--index", type=int, default=0, help="ciphertext block index for tamper")
    cbc.add_argument("--mask", default="0001", help="16-bit XOR mask for tamper")

    subparsers.add_parser("self-test", help="run the canonical algorithm checks")
    return parser


def _run(args: argparse.Namespace) -> int:
    if args.command == "block":
        data = parse_hex(args.data, 16, "data")
        key = parse_hex(args.key, 16, "key")
        result = encrypt_block(data, key) if args.operation == "encrypt" else decrypt_block(data, key)
        print(format_hex(result))
        return 0

    if args.command == "text":
        key = parse_hex(args.key, 16, "key")
        if args.operation == "encrypt":
            ciphertext = ascii_encrypt(args.data, key)
            print(f"ciphertext_hex={ciphertext.hex().upper()}")
            print(f"ciphertext_display={bytes_to_display(ciphertext)}")
        else:
            plaintext = ascii_decrypt(_hex_bytes(args.data), key)
            print(plaintext)
        return 0

    if args.command == "multi":
        data = parse_hex(args.data, 16, "data")
        key1 = parse_hex(args.key1, 16, "key1")
        key2 = parse_hex(args.key2, 16, "key2")
        if args.mode == "double":
            result = double_encrypt(data, key1, key2) if args.operation == "encrypt" else double_decrypt(data, key1, key2)
        else:
            key3 = None if args.mode == "ede2" or args.key3 is None else parse_hex(args.key3, 16, "key3")
            result = (
                triple_encrypt(data, key1, key2, key3, args.mode)
                if args.operation == "encrypt"
                else triple_decrypt(data, key1, key2, key3, args.mode)
            )
        print(format_hex(result))
        return 0

    if args.command == "mitm":
        pairs = [_parse_pair(pair) for pair in args.pair]
        candidates = meet_in_the_middle(pairs, max_results=args.max_results)
        if args.max_results is not None and len(candidates) >= args.max_results:
            print("result limit reached; search may be incomplete", file=sys.stderr)
        if not candidates:
            print("no candidate key pair")
        else:
            for key1, key2 in candidates:
                print(f"K1={format_hex(key1)} K2={format_hex(key2)}")
        return 0

    if args.command == "cbc":
        key = parse_hex(args.key, 16, "key")
        iv = parse_hex(args.iv, 16, "iv")
        if args.operation == "encrypt":
            ciphertext = cbc_encrypt(args.data.encode("ascii"), key, iv)
            print(f"iv={format_hex(iv)}")
            print(f"ciphertext_hex={ciphertext.hex().upper()}")
            return 0
        ciphertext = _hex_bytes(args.data)
        if args.operation == "decrypt":
            plaintext = cbc_decrypt(ciphertext, key, iv)
            print(bytes_to_display(plaintext))
            return 0
        modified = tamper_ciphertext(ciphertext, args.index, parse_hex(args.mask, 16, "mask"))
        print(f"tampered_ciphertext_hex={modified.hex().upper()}")
        return 0

    if args.command == "self-test":
        plaintext = 0xD728
        key = 0x4AF5
        ciphertext = encrypt_block(plaintext, key)
        if ciphertext != 0x24EC or decrypt_block(ciphertext, key) != plaintext:
            raise AssertionError("canonical S-AES vector failed")
        if expand_key(0x2D55) != (0x2D55, 0xBCE9, 0xA34A):
            raise AssertionError("key expansion example failed")
        print("self-test: PASS")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (TypeError, ValueError, UnicodeError, AssertionError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
