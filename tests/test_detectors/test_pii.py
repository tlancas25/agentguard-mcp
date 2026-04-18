"""Tests for the PII detector."""

from __future__ import annotations

import pytest

from agentguard.detectors.pii import detect, detect_in_tool_args


class TestSSNDetection:
    """Social Security Number detection."""

    def test_ssn_with_dashes(self) -> None:
        result = detect("Employee SSN: 123-45-6789")
        assert result.matched
        assert "ssn" in result.types_found

    def test_ssn_with_spaces(self) -> None:
        result = detect("SSN 234 56 7890")
        assert result.matched

    def test_invalid_ssn_not_flagged(self) -> None:
        # 000 prefix is invalid SSN
        result = detect("000-45-6789")
        assert "ssn" not in (result.types_found or [])


class TestCreditCardDetection:
    """Credit card number detection."""

    def test_visa_number(self) -> None:
        result = detect("Card: 4111 1111 1111 1111")
        assert result.matched
        assert "credit_card" in result.types_found

    def test_mastercard_number(self) -> None:
        result = detect("5500 0000 0000 0004")
        assert result.matched

    def test_amex_number(self) -> None:
        result = detect("3714 496353 98431")
        assert result.matched


class TestEmailDetection:
    """Email address detection."""

    def test_standard_email(self) -> None:
        result = detect("Contact me at user@example.com")
        assert result.matched
        assert "email" in result.types_found

    def test_email_with_plus(self) -> None:
        result = detect("user+tag@company.org")
        assert result.matched

    def test_fake_email_not_flagged(self) -> None:
        result = detect("not-an-email-at-all")
        assert "email" not in (result.types_found or [])


class TestPhoneDetection:
    """US phone number detection."""

    def test_us_phone_formatted(self) -> None:
        result = detect("Call me at (555) 867-5309")
        assert result.matched
        assert "phone_us" in result.types_found

    def test_us_phone_dashes(self) -> None:
        result = detect("Phone: 800-555-1234")
        assert result.matched


class TestStreetAddressDetection:
    """Street address detection."""

    def test_standard_address(self) -> None:
        result = detect("Deliver to 123 Main Street, Springfield")
        assert result.matched
        assert "street_address" in result.types_found


class TestCleanContent:
    """Legitimate content that should not be flagged."""

    def test_empty_string(self) -> None:
        result = detect("")
        assert not result.matched

    def test_code_not_flagged(self) -> None:
        result = detect("for i in range(10): print(i)")
        assert not result.matched

    def test_url_not_flagged(self) -> None:
        result = detect("https://api.example.com/v1/users")
        assert not result.matched


class TestToolArgsScanning:
    """PII detection across tool argument dicts."""

    def test_pii_in_string_arg(self) -> None:
        args = {"data": "Patient SSN: 987-65-4321"}
        result = detect_in_tool_args(args)
        assert result.matched
        assert "ssn" in result.types_found

    def test_clean_args(self) -> None:
        args = {"filename": "report.pdf", "page": 1}
        result = detect_in_tool_args(args)
        assert not result.matched


class TestNISTControls:
    """Verify NIST controls are correctly referenced."""

    def test_detection_has_nist_controls(self) -> None:
        result = detect("123-45-6789")
        assert "SI-10" in result.nist_controls
        assert "SC-28" in result.nist_controls
