"""Encryption, key versioning, and rotation."""
import base64
import os

import pytest

import app as crypto_app


class TestKeyValidation:
    def test_a_short_key_is_rejected_not_padded(self):
        short = base64.b64encode(os.urandom(16)).decode()
        with pytest.raises(RuntimeError, match="exactly 32 bytes"):
            crypto_app._load_encryption_key(short)

    def test_a_long_key_is_rejected_not_truncated(self):
        long = base64.b64encode(os.urandom(48)).decode()
        with pytest.raises(RuntimeError, match="exactly 32 bytes"):
            crypto_app._load_encryption_key(long)

    def test_invalid_base64_is_rejected(self):
        with pytest.raises(RuntimeError, match="base64"):
            crypto_app._load_encryption_key("not!valid!base64!")

    def test_a_valid_key_round_trips(self):
        raw = os.urandom(32)
        assert crypto_app._load_encryption_key(base64.b64encode(raw).decode()) == raw


class TestRoundTrip:
    @pytest.mark.parametrize(
        "plaintext",
        ["Jordan Patient", "+15555550123", "", "  spaces  ", "emoji 🏥", "a" * 5000],
    )
    def test_values_round_trip(self, plaintext):
        assert crypto_app.aes_decrypt(crypto_app.aes_encrypt(plaintext)) == plaintext

    def test_the_same_plaintext_produces_different_ciphertext(self):
        """A fresh nonce per write, so equal values are not linkable."""
        assert crypto_app.aes_encrypt("same") != crypto_app.aes_encrypt("same")

    def test_ciphertext_does_not_contain_the_plaintext(self):
        assert "Jordan" not in crypto_app.aes_encrypt("Jordan Patient")

    def test_tampered_ciphertext_is_rejected(self):
        from cryptography.exceptions import InvalidTag

        token = crypto_app.aes_encrypt("Jordan Patient")
        version, _, body = token.partition(":")
        raw = bytearray(base64.b64decode(body))
        raw[-1] ^= 0xFF
        tampered = f"{version}:{base64.b64encode(bytes(raw)).decode()}"
        with pytest.raises(InvalidTag):
            crypto_app.aes_decrypt(tampered)


class TestKeyVersioning:
    def test_new_values_carry_the_current_version(self):
        token = crypto_app.aes_encrypt("Jordan Patient")
        assert token.startswith(f"v{crypto_app.CURRENT_KEY_VERSION}:")

    def test_legacy_unversioned_values_still_decrypt(self):
        """Rows written before versioning must remain readable."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        ct = AESGCM(crypto_app.KEY_RING[1]).encrypt(nonce, b"Legacy Patient", None)
        legacy = base64.b64encode(nonce + ct).decode()
        assert ":" not in legacy, "base64 must not collide with the version separator"
        assert crypto_app.aes_decrypt(legacy) == "Legacy Patient"

    def test_legacy_values_are_flagged_for_rotation(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        ct = AESGCM(crypto_app.KEY_RING[1]).encrypt(nonce, b"Legacy", None)
        assert crypto_app.aes_needs_rotation(base64.b64encode(nonce + ct).decode())

    def test_current_values_are_not_flagged(self):
        assert not crypto_app.aes_needs_rotation(crypto_app.aes_encrypt("Current"))

    def test_empty_values_are_not_flagged(self):
        assert not crypto_app.aes_needs_rotation(None)
        assert not crypto_app.aes_needs_rotation("")


class TestUnreadableValues:
    def test_decrypt_optional_degrades_instead_of_raising(self):
        """One corrupt row must not take down a page that renders many."""
        assert crypto_app._decrypt_optional("v1:not-real-ciphertext") == crypto_app.UNREADABLE

    def test_decrypt_optional_handles_empty(self):
        assert crypto_app._decrypt_optional(None) == ""
        assert crypto_app._decrypt_optional("") == ""
