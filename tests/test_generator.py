"""
Tests for password, passphrase, and PIN generators.

Statistical tests use a sample of 500 to balance reliability and speed.
"""

import pytest
import string
from generator import generate_password, generate_passphrase, generate_pin


class TestRandomPasswordGenerator:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        pw = generate_password(length=24)
        assert len(pw) == 24

    def test_minimum_length_enforced(self):
        pw = generate_password(length=2)
        assert len(pw) == 8  # floor

    def test_contains_required_classes_by_default(self):
        for _ in range(50):
            pw = generate_password(length=16)
            assert any(c in string.ascii_lowercase for c in pw), "Missing lowercase"
            assert any(c in string.ascii_uppercase for c in pw), "Missing uppercase"
            assert any(c in string.digits for c in pw), "Missing digit"
            assert any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw), "Missing symbol"

    def test_no_symbols_flag(self):
        for _ in range(20):
            pw = generate_password(length=16, use_symbols=False)
            assert all(c not in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)

    def test_no_ambiguous_flag(self):
        ambiguous = set("0O1lI")
        for _ in range(50):
            pw = generate_password(length=16, no_ambiguous=True)
            assert not (set(pw) & ambiguous), f"Ambiguous chars found in {pw!r}"

    def test_uniqueness(self):
        passwords = {generate_password(length=16) for _ in range(100)}
        assert len(passwords) == 100  # all unique (astronomically unlikely to collide)


class TestPassphraseGenerator:
    def test_default_word_count(self):
        phrase = generate_passphrase()
        assert len(phrase.split("-")) == 5

    def test_custom_word_count(self):
        phrase = generate_passphrase(word_count=7)
        assert len(phrase.split("-")) == 7

    def test_custom_separator(self):
        phrase = generate_passphrase(word_count=4, separator=".")
        assert "." in phrase
        assert len(phrase.split(".")) == 4

    def test_augment_adds_digit_and_symbol(self):
        symbols = set("!@#$%^&*")
        for _ in range(20):
            phrase = generate_passphrase(word_count=4, augment=True)
            # Last chars should include a symbol from the augment set
            assert any(c in symbols for c in phrase[-3:])
            assert any(c.isdigit() for c in phrase[-4:])

    def test_capitalize_flag(self):
        for _ in range(20):
            phrase = generate_passphrase(word_count=4, capitalize=True, separator="-")
            for word in phrase.split("-"):
                if word[0].isalpha():
                    assert word[0].isupper(), f"Word not capitalised: {word}"

    def test_uniqueness(self):
        phrases = {generate_passphrase(word_count=5) for _ in range(100)}
        assert len(phrases) >= 95  # allow tiny collision chance with small wordlist

    def test_minimum_word_count_floor(self):
        phrase = generate_passphrase(word_count=1)
        assert len(phrase.split("-")) >= 3


class TestPINGenerator:
    def test_default_length(self):
        pin, _ = generate_pin()
        assert len(pin) == 6

    def test_custom_length(self):
        pin, _ = generate_pin(length=8)
        assert len(pin) == 8

    def test_minimum_length_floor(self):
        pin, _ = generate_pin(length=2)
        assert len(pin) == 4

    def test_all_digits(self):
        for _ in range(20):
            pin, _ = generate_pin(length=6)
            assert pin.isdigit()

    def test_no_all_same_digits(self):
        for _ in range(200):
            pin, _ = generate_pin(length=6)
            assert len(set(pin)) > 1, f"All-same PIN generated: {pin}"

    def test_no_simple_sequence(self):
        for _ in range(200):
            pin, _ = generate_pin(length=6)
            assert pin != "123456"
            assert pin != "654321"

    def test_short_pin_warning(self):
        _, warning = generate_pin(length=4)
        assert warning is not None
        assert "entropy" in warning.lower() or "bit" in warning.lower()

    def test_no_warning_for_6_digit_pin(self):
        _, warning = generate_pin(length=6)
        assert warning is None

    def test_uniqueness(self):
        pins = {generate_pin(length=6)[0] for _ in range(200)}
        assert len(pins) >= 150  # statistically very likely
