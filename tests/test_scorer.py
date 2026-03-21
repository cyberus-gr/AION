"""
Integration tests for the scoring pipeline.

These tests verify end-to-end behaviour without mocking any internals.
"""

import pytest
from analyzer import analyze


class TestWellKnownPasswords:
    def test_common_password_scores_very_weak(self):
        result = analyze("password")
        assert result.score < 25
        assert result.is_common is True

    def test_common_password_leet_variant_still_weak(self):
        result = analyze("p@ssw0rd")
        assert result.score < 25
        assert result.is_common is True

    def test_short_password_capped(self):
        # Even a character-diverse short password is capped at 30
        result = analyze("Ab1!")
        assert result.score <= 30

    def test_long_random_looking_password_scores_strong(self):
        result = analyze("X7#mK9$pL2@wQ5!z")
        assert result.score >= 75

    def test_empty_password_scores_zero(self):
        result = analyze("")
        assert result.score == 0

    def test_all_lowercase_short(self):
        result = analyze("hello")
        assert result.score < 30

    def test_good_passphrase_scores_fair_or_better(self):
        # Typical diceware passphrase — long, no common patterns
        result = analyze("maple-frost-sword-ember-tiger")
        assert result.score >= 40


class TestCharacterClassFlags:
    def test_all_classes_detected(self):
        result = analyze("Abc123!@#")
        assert result.has_lower is True
        assert result.has_upper is True
        assert result.has_digit is True
        assert result.has_symbol is True

    def test_only_digits_detected(self):
        result = analyze("123456789")
        assert result.has_lower is False
        assert result.has_upper is False
        assert result.has_digit is True
        assert result.has_symbol is False


class TestSuggestions:
    def test_common_password_gives_only_dictionary_suggestion(self):
        result = analyze("password")
        assert len(result.suggestions) == 1
        assert "breach" in result.suggestions[0].message.lower() or \
               "database" in result.suggestions[0].message.lower()

    def test_short_password_suggests_length(self):
        result = analyze("ab1")
        messages = [s.message for s in result.suggestions]
        assert any("12" in m or "extend" in m.lower() or "length" in m.lower()
                   for m in messages)

    def test_missing_symbol_is_suggested(self):
        result = analyze("Abcdefgh123456")
        messages = [s.message for s in result.suggestions]
        assert any("symbol" in m.lower() for m in messages)
