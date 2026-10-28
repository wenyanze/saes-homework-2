from __future__ import annotations

import unittest
from concurrent.futures import CancelledError

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
    gf4_multiply,
    inverse_mix_columns,
    inverse_sub_nibbles,
    meet_in_the_middle,
    mix_columns,
    parse_hex,
    shift_rows,
    sub_nibbles,
    tamper_ciphertext,
    triple_decrypt,
    triple_encrypt,
)


class SaesPrimitiveTests(unittest.TestCase):
    def test_appendix_d_key_expansion_example(self) -> None:
        self.assertEqual(expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))

    def test_appendix_d_transform_examples(self) -> None:
        self.assertEqual(sub_nibbles(0x8A1C), 0x604C)
        self.assertEqual(shift_rows(0x604C), 0x6C40)
        self.assertEqual(mix_columns(0x6C40), 0x3743)
        self.assertEqual(inverse_mix_columns(0x3743), 0x6C40)
        self.assertEqual(inverse_sub_nibbles(sub_nibbles(0x1234)), 0x1234)
        self.assertEqual(gf4_multiply(0x4, 0xC), 0x5)

    def test_canonical_cross_program_vector(self) -> None:
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_block_round_trip_for_representative_values(self) -> None:
        for plaintext in (0x0000, 0x0001, 0x1234, 0x7FFF, 0xFFFF):
            for key in (0x0000, 0x1A2B, 0x4AF5, 0xFFFF):
                ciphertext = encrypt_block(plaintext, key)
                self.assertEqual(decrypt_block(ciphertext, key), plaintext)

    def test_parser_and_fixed_width_format(self) -> None:
        self.assertEqual(parse_hex("0xd728", 16), 0xD728)
        self.assertEqual(format_hex(0x2A), "002A")
        with self.assertRaises(ValueError):
            parse_hex("10000", 16)


class SaesExtensionTests(unittest.TestCase):
    def test_ascii_extension_is_reversible(self) -> None:
        ciphertext = ascii_encrypt("S-AES demo", 0x4AF5)
        self.assertEqual(ciphertext.hex().upper(), "227902476278908FD6F4D35D")
        self.assertEqual(ascii_decrypt(ciphertext, 0x4AF5), "S-AES demo")
        self.assertIn("\\x", bytes_to_display(ciphertext))

    def test_cbc_known_result_and_round_trip(self) -> None:
        plaintext = b"CBC demo!"
        ciphertext = cbc_encrypt(plaintext, 0x4AF5, 0x1234)
        self.assertEqual(ciphertext.hex().upper(), "3ECE88E232EAB81A87F8")
        self.assertEqual(cbc_decrypt(ciphertext, 0x4AF5, 0x1234), plaintext)

    def test_cbc_tampering_changes_decryption(self) -> None:
        plaintext = b"CBC tamper test"
        ciphertext = cbc_encrypt(plaintext, 0x4AF5, 0x1234)
        modified = tamper_ciphertext(ciphertext, 0, 0x0001)
        self.assertNotEqual(modified, ciphertext)
        changed = cbc_decrypt(modified, 0x4AF5, 0x1234)
        self.assertNotEqual(changed[:2], plaintext[:2])
        self.assertEqual(int.from_bytes(changed[2:4], "big"), int.from_bytes(plaintext[2:4], "big") ^ 1)
        self.assertEqual(changed[4:], plaintext[4:])
        # Also verify unaffected preceding blocks when changing an interior block.
        modified = tamper_ciphertext(ciphertext, 2, 0x8001)
        changed = cbc_decrypt(modified, 0x4AF5, 0x1234)
        self.assertEqual(changed[:4], plaintext[:4])
        self.assertNotEqual(changed[4:6], plaintext[4:6])
        self.assertEqual(int.from_bytes(changed[6:8], "big"), int.from_bytes(plaintext[6:8], "big") ^ 0x8001)
        self.assertEqual(changed[8:], plaintext[8:])

    def test_text_boundaries_and_padding(self) -> None:
        for text in ("", "A", "AB", "ABC", "A\x00", "\x00\x00"):
            with self.subTest(text=text):
                encrypted = ascii_encrypt(text, 0x4AF5)
                self.assertEqual(len(encrypted), (len(text) // 2 + 1) * 2)
                self.assertEqual(ascii_decrypt(encrypted, 0x4AF5), text)
                data = text.encode("ascii")
                self.assertEqual(cbc_decrypt(cbc_encrypt(data, 0x4AF5, 0x1234), 0x4AF5, 0x1234), data)
        with self.assertRaises(ValueError):
            ascii_encrypt("中文", 0x4AF5)

    def test_invalid_ciphertext_and_padding(self) -> None:
        for data in (b"", b"x", b"xyz"):
            with self.assertRaises(ValueError):
                ascii_decrypt(data, 0x4AF5)
            with self.assertRaises(ValueError):
                cbc_decrypt(data, 0x4AF5, 0x1234)
        # Construct deterministic invalid padded plaintext, rather than guessing a wrong key.
        for block in (0x4100, 0x4103, 0x0102):
            with self.assertRaises(ValueError):
                ascii_decrypt(encrypt_block(block, 0x4AF5).to_bytes(2, "big"), 0x4AF5)
            with self.assertRaises(ValueError):
                cbc_decrypt(encrypt_block(block ^ 0x1234, 0x4AF5).to_bytes(2, "big"), 0x4AF5, 0x1234)

    def test_invalid_numeric_inputs(self) -> None:
        for value in (-1, 65536, True, "1234"):
            with self.assertRaises((TypeError, ValueError)):
                encrypt_block(value, 0)
            with self.assertRaises((TypeError, ValueError)):
                encrypt_block(0, value)
            with self.assertRaises((TypeError, ValueError)):
                cbc_encrypt(b"", 0, value)
        for index in (-1, 1, True):
            with self.assertRaises((TypeError, ValueError)):
                tamper_ciphertext(b"AB", index, 1)
        for text in ("", "GG", "10000", "-1"):
            with self.assertRaises(ValueError):
                parse_hex(text, 16)

    def test_display_escapes_literal_backslashes(self) -> None:
        self.assertEqual(bytes_to_display(bytes([1])), r"\x01")
        self.assertEqual(bytes_to_display(b"\\x01"), r"\\x01")
        self.assertNotEqual(bytes_to_display(bytes([1])), bytes_to_display(b"\\x01"))

    def test_double_and_triple_modes(self) -> None:
        plaintext = 0x1234
        key1, key2, key3 = 0x1A2B, 0x3C4D, 0x5E6F
        double_ciphertext = double_encrypt(plaintext, key1, key2)
        self.assertEqual(double_ciphertext, 0xF04D)
        self.assertEqual(double_decrypt(double_ciphertext, key1, key2), plaintext)
        expected = {"eee": 0x6C0F, "ede": 0x5284, "ede2": 0x3044}
        for mode in ("eee", "ede", "ede2"):
            ciphertext = triple_encrypt(plaintext, key1, key2, key3, mode)
            self.assertEqual(ciphertext, expected[mode])
            self.assertEqual(triple_decrypt(ciphertext, key1, key2, key3, mode), plaintext)


class MeetInTheMiddleTests(unittest.TestCase):
    def test_invalid_limits_and_empty_pairs(self) -> None:
        for limit in (0, -1, True, 1.5, "1"):
            with self.assertRaises((TypeError, ValueError)):
                meet_in_the_middle([(0, 0)], max_results=limit)
        with self.assertRaises(ValueError):
            meet_in_the_middle([])

    def test_cancellation(self) -> None:
        with self.assertRaises(CancelledError):
            meet_in_the_middle([(0, 0)], cancelled=lambda: True)

    def test_result_limit(self) -> None:
        pair = (0x1234, double_encrypt(0x1234, 0, 0))
        candidates = meet_in_the_middle([pair], max_results=1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(double_encrypt(pair[0], *candidates[0]), pair[1])

    def test_three_known_pairs_recover_the_key_pair(self) -> None:
        key1, key2 = 0x1A2B, 0x3C4D
        pairs = tuple(
            (plaintext, double_encrypt(plaintext, key1, key2))
            for plaintext in (0x1234, 0xBEEF, 0xCAFE)
        )
        progress = []
        candidates = meet_in_the_middle(pairs, progress=lambda *event: progress.append(event))
        self.assertIn(("forward", 65536, 65536), progress)
        self.assertEqual(progress[-1], ("backward", 65536, 65536))
        self.assertIn((key1, key2), candidates)
        self.assertEqual(candidates, [(key1, key2)])


if __name__ == "__main__":
    unittest.main()
