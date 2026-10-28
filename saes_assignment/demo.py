"""Run local demonstrations; independent cross-testing uses cross_test.py."""

from __future__ import annotations

from saes import (
    ascii_encrypt,
    ascii_decrypt,
    encrypt_block,
    decrypt_block,
    cbc_decrypt,
    cbc_encrypt,
    double_encrypt,
    format_hex,
    meet_in_the_middle,
    tamper_ciphertext,
    triple_encrypt,
)


def main() -> None:
    key = 0x4AF5
    print("[1] basic")
    ciphertext = encrypt_block(0xD728, key)
    print(f"P=D728 K=4AF5 C={format_hex(ciphertext)} Decrypt={format_hex(decrypt_block(ciphertext, key))}")
    print("[2] independent cross-test: run cross_test.py with --peer-dir")

    text_ciphertext = ascii_encrypt("S-AES demo", key)
    print("[3] ascii")
    print(f"plaintext=S-AES demo ciphertext={text_ciphertext.hex().upper()}")
    print(f"decrypted={ascii_decrypt(text_ciphertext, key)}")

    key1, key2, key3 = 0x1A2B, 0x3C4D, 0x5E6F
    print("[4] multiple encryption")
    print(f"double={format_hex(double_encrypt(0x1234, key1, key2))}")
    print(f"triple_eee={format_hex(triple_encrypt(0x1234, key1, key2, key3, 'eee'))}")
    print(f"triple_ede={format_hex(triple_encrypt(0x1234, key1, key2, key3, 'ede'))}")
    print(f"triple_ede2={format_hex(triple_encrypt(0x1234, key1, key2, mode='ede2'))}")
    pairs = [(0x1234, 0xF04D), (0xBEEF, 0x62E6), (0xCAFE, 0x8ACE)]
    candidates = meet_in_the_middle(pairs)
    print("mitm=" + ", ".join(f"{format_hex(a)}+{format_hex(b)}" for a, b in candidates))

    print("[5] cbc")
    plaintext = b"CBC tamper demonstration"
    ciphertext = cbc_encrypt(plaintext, key, 0x1234)
    tampered = tamper_ciphertext(ciphertext, 0, 0x0001)
    print(f"iv=1234 ciphertext={ciphertext.hex().upper()}")
    print(f"tampered={tampered.hex().upper()}")
    print(f"original={cbc_decrypt(ciphertext, key, 0x1234)!r}")
    print(f"modified={cbc_decrypt(tampered, key, 0x1234)!r}")


if __name__ == "__main__":
    main()
