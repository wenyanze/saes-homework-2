"""Regression checks for CBC results using hidden Tk widgets."""

import tkinter as tk
import unittest

from app import SaesApplication
from saes import cbc_encrypt


class CbcGuiTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            self.app = SaesApplication()
        except tk.TclError as error:
            self.skipTest(f"Tk display unavailable: {error}")
        self.app.withdraw()
        self.addCleanup(self.app.destroy)
        self.errors = []
        self.app._report_error = lambda error: self.errors.append(str(error))
        self.app._encrypt_cbc()
        self.app._compare_cbc()
        self.assertEqual(self.app.cbc_original_var.get(), "CBC tamper demonstration")

    def assert_results_empty(self) -> None:
        for variable in (self.app.cbc_tampered_var, self.app.cbc_original_var, self.app.cbc_modified_var):
            self.assertEqual(variable.get(), "")

    def test_reencrypt_clears_previous_comparison(self) -> None:
        self.app.cbc_plain_var.set("NEW MESSAGE")
        self.app._encrypt_cbc()
        self.assertEqual(self.app.cbc_original_var.get(), "")
        self.assertEqual(self.app.cbc_modified_var.get(), "")
        self.assertEqual(self.app.cbc_cipher_var.get(), cbc_encrypt(b"NEW MESSAGE", 0x4AF5, 0x1234).hex().upper())
        self.app._compare_cbc()
        self.assertEqual(self.app.cbc_original_var.get(), "NEW MESSAGE")
        self.assertFalse(self.errors)

    def test_invalid_tamper_does_not_publish_new_ciphertext(self) -> None:
        self.app.cbc_plain_var.set("NEW MESSAGE")
        self.app.cbc_index_var.set("999")
        self.app._encrypt_cbc()
        self.assertEqual(self.app.cbc_cipher_var.get(), "")
        self.assert_results_empty()
        self.assertTrue(self.errors)

    def test_failed_compare_clears_results_and_preserves_input(self) -> None:
        ciphertext = self.app.cbc_cipher_var.get()
        self.app.cbc_index_var.set("999")
        self.app._compare_cbc()
        self.assertEqual(self.app.cbc_cipher_var.get(), ciphertext)
        self.assert_results_empty()
        self.app.cbc_index_var.set("0")
        self.app.cbc_cipher_var.set("XYZ")
        self.app._compare_cbc()
        self.assertEqual(self.app.cbc_cipher_var.get(), "XYZ")
        self.assert_results_empty()
        self.assertEqual(len(self.errors), 2)

    def test_padding_damage_displays_current_original_and_failure(self) -> None:
        # Change the previous ciphertext block to flip the final padding byte.
        ciphertext = self.app.cbc_cipher_var.get()
        self.app.cbc_index_var.set(str(len(ciphertext) // 4 - 2))
        self.app._compare_cbc()
        self.assertEqual(self.app.cbc_original_var.get(), "CBC tamper demonstration")
        self.assertIn("解密失败", self.app.cbc_modified_var.get())
        self.assertTrue(self.app.cbc_tampered_var.get())
        self.assertFalse(self.errors)


if __name__ == "__main__":
    unittest.main()
