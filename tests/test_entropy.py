"""
Unit tests for entropy calculations.
"""

import math
import pytest
from analyzer.entropy import charset_entropy, conditional_entropy, entropy_label


class TestCharsetEntropy:
    def test_empty_password_is_zero(self):
        assert charset_entropy("") == 0.0

    def test_lowercase_only_charset_size_26(self):
        bits = charset_entropy("abcdefgh")   # 8 chars, pool=26
        expected = 8 * math.log2(26)
        assert abs(bits - expected) < 0.01

    def test_mixed_charset_larger_pool(self):
        lower_only = charset_entropy("abcdefgh")
        mixed = charset_entropy("Abcdefg1")  # adds uppercase + digit
        assert mixed > lower_only

    def test_longer_password_more_entropy(self):
        short = charset_entropy("Abc1!")
        long_ = charset_entropy("Abc1!Xyz9@")
        assert long_ > short

    def test_adding_symbol_class_increases_entropy(self):
        no_sym = charset_entropy("Abcdef12")
        with_sym = charset_entropy("Abcdef1!")
        assert with_sym > no_sym


class TestConditionalEntropy:
    def test_highly_repetitive_lower_than_charset(self):
        password = "aaaaaaaaaaaaaaaaaaaaaaaa"
        cond = conditional_entropy(password)
        raw = charset_entropy(password)
        assert cond < raw

    def test_random_looking_close_to_charset(self):
        password = "X7#mK9$pL2@wQ5!z"
        cond = conditional_entropy(password)
        raw = charset_entropy(password)
        # Should be within 30% of raw for a random-looking password
        assert cond >= raw * 0.70

    def test_short_password_returns_charset_entropy(self):
        password = "abc"
        assert conditional_entropy(password) == charset_entropy(password)


class TestEntropyLabel:
    def test_very_low(self):
        assert entropy_label(10) == "Very Low"

    def test_low(self):
        assert entropy_label(30) == "Low"

    def test_moderate(self):
        assert entropy_label(50) == "Moderate"

    def test_high(self):
        assert entropy_label(80) == "High"

    def test_very_high(self):
        assert entropy_label(120) == "Very High"
