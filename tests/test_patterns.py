"""
Unit tests for pattern detectors.
"""

import pytest
from analyzer.patterns import (
    detect_keyboard_walk,
    detect_repeating_chars,
    detect_sequential_chars,
    detect_date_pattern,
    normalize_leet,
    all_penalties,
)


class TestKeyboardWalk:
    def test_qwerty_triggers_penalty(self):
        penalties = detect_keyboard_walk("qwerty")
        assert len(penalties) == 1
        assert penalties[0].factor <= 0.5

    def test_long_walk_harsher_penalty(self):
        short = detect_keyboard_walk("qwert")
        long_ = detect_keyboard_walk("qwertyuiop")
        assert long_[0].factor < short[0].factor

    def test_no_walk_no_penalty(self):
        assert detect_keyboard_walk("X7#mK9$p") == []

    def test_numeric_walk_detected(self):
        penalties = detect_keyboard_walk("12345678")
        assert len(penalties) == 1


class TestRepeatingChars:
    def test_triple_repeat_detected(self):
        penalties = detect_repeating_chars("aaabbb")
        assert len(penalties) == 1

    def test_double_repeat_not_penalised(self):
        assert detect_repeating_chars("aabb") == []

    def test_no_repeat_no_penalty(self):
        assert detect_repeating_chars("abcdefg") == []


class TestSequentialChars:
    def test_ascending_detected(self):
        penalties = detect_sequential_chars("abcd1234")
        assert len(penalties) >= 1

    def test_descending_detected(self):
        penalties = detect_sequential_chars("dcbaZYXW")
        assert len(penalties) >= 1

    def test_short_run_not_penalised(self):
        assert detect_sequential_chars("abc") == []


class TestDatePattern:
    def test_year_detected(self):
        penalties = detect_date_pattern("summer2023!")
        assert len(penalties) == 1

    def test_slash_date_detected(self):
        penalties = detect_date_pattern("john5/15pass")
        assert len(penalties) == 1

    def test_no_date_no_penalty(self):
        assert detect_date_pattern("XKm$7!zQ") == []


class TestLeetNormalizer:
    def test_basic_substitutions(self):
        assert normalize_leet("p@ssw0rd") == "password"
        assert normalize_leet("h3ll0") == "hello"

    def test_no_substitution_unchanged(self):
        assert normalize_leet("abcdef") == "abcdef"

    def test_case_folded(self):
        assert normalize_leet("HELLO") == "hello"
