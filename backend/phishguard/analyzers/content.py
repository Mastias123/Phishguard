"""Content analyzer for phishing indicators in email body and subject."""

import re
from typing import List, Set

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailMessage


class ContentAnalyzer(BaseAnalyzer):
    """Detect phishing patterns in email content and subject."""

    # Generic notification keywords without legitimate context usually indicate phishing
    GENERIC_NOTIFICATION_KEYWORDS = {
        "parcel",
        "delivery",
        "shipment",
        "package",
        "tracking",
        "verify account",
        "confirm identity",
        "update payment",
        "suspicious activity",
        "unusual activity",
        "urgent action",
        "click here",
        "download",
        "reactivate",
    }

    # Identifiers that legitimate transactional emails should contain
    IDENTIFIER_KEYWORDS = {
        "tracking",
        "order",
        "reference",
        "ticket",
        "invoice",
        "receipt",
        "number",
        "id",
        "code",
        "confirmation",
    }

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze email content for phishing patterns."""
        signals: List[DetectionSignal] = []

        body = (email.body.get_content() if email.body else "").lower()
        subject = (email.headers.subject or "").lower()
        combined = f"{subject} {body}"

        # Check for generic notification without identifiers (common phishing pattern)
        if self._has_generic_notification_theme(combined) and not self._has_identifier_info(combined):
            signals.append(
                DetectionSignal(
                    signal_type="content",
                    confidence=0.7,
                    reason="Generic notification theme without tracking/order numbers or specific context.",
                    severity="medium",
                )
            )

        # Check for obfuscation patterns (soft hyphens, zero-width chars, etc.)
        if self._has_obfuscation_patterns(body):
            signals.append(
                DetectionSignal(
                    signal_type="content",
                    confidence=0.65,
                    reason="Email body contains unusual Unicode obfuscation (soft hyphens, zero-width characters).",
                    severity="medium",
                )
            )

        # Check for credential request patterns
        if self._has_credential_request(combined):
            signals.append(
                DetectionSignal(
                    signal_type="content",
                    confidence=0.8,
                    reason="Email requests password, PIN, or security credentials.",
                    severity="high",
                )
            )

        # Check for urgency/threat language combined with action request
        if self._has_threat_urgency(combined) and self._has_call_to_action(body):
            signals.append(
                DetectionSignal(
                    signal_type="content",
                    confidence=0.75,
                    reason="Email combines threat/urgency language with immediate action request.",
                    severity="high",
                )
            )

        return signals

    @classmethod
    def _has_generic_notification_theme(cls, text: str) -> bool:
        """Check if text contains generic notification keywords."""
        return any(keyword in text for keyword in cls.GENERIC_NOTIFICATION_KEYWORDS)

    @classmethod
    def _has_identifier_info(cls, text: str) -> bool:
        """Check if text contains legitimate identifier/tracking information."""
        for keyword in cls.IDENTIFIER_KEYWORDS:
            if keyword in text:
                # Look for actual numbers/codes following the keyword
                pattern = rf"{keyword}[:\s]+([\w\-]+)"
                if re.search(pattern, text, re.IGNORECASE):
                    return True
        return False

    @staticmethod
    def _has_obfuscation_patterns(text: str) -> bool:
        """Detect unusual Unicode patterns used to evade filters."""
        # Soft hyphens (U+00AD) and zero-width joiners in words suggest obfuscation
        if "\u00ad" in text:  # Soft hyphen
            return True
        if "\u200b" in text:  # Zero-width space
            return True
        if "\u200d" in text:  # Zero-width joiner
            return True
        if "\u200c" in text:  # Zero-width non-joiner
            return True
        # Excessive Unicode combining marks in short sequences (homoglyph indicators)
        combining_marks = len(re.findall(r"[\u0300-\u036f]", text))
        text_length = len(text)
        if text_length > 100 and combining_marks > text_length * 0.02:  # >2% combining marks
            return True
        return False

    @staticmethod
    def _has_credential_request(text: str) -> bool:
        """Check for requests for passwords, PINs, or credentials."""
        patterns = [
            r"password",
            r"passphrase",
            r"pin(\s+code)?",
            r"security\s+code",
            r"verification\s+code",
            r"one[- ]time\s+password",
            r"otp",
            r"two[- ]factor",
            r"2fa",
            r"cvv",
            r"card\s+details",
            r"social\s+security",
            r"ssn",
            r"account\s+number",
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

    @staticmethod
    def _has_threat_urgency(text: str) -> bool:
        """Check for threatening or urgent language patterns."""
        patterns = [
            r"urgent",
            r"immediately",
            r"within\s+\d+\s+hours?",
            r"within\s+\d+\s+days?",
            r"suspended",
            r"deactivated?",
            r"locked",
            r"compromised",
            r"unauthorized",
            r"verify now",
            r"confirm now",
            r"act now",
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

    @staticmethod
    def _has_call_to_action(text: str) -> bool:
        """Check for clear call-to-action phrases."""
        patterns = [
            r"click\s+(here|below|link)",
            r"tap\s+(here|below)",
            r"download",
            r"sign\s+in",
            r"log\s+in",
            r"verify",
            r"confirm",
            r"update",
            r"re[-]?activate",
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
