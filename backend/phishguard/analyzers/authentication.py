"""Authentication analyzer for SPF, DKIM, and DMARC failures."""

import re
from typing import List, Optional

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailMessage


class AuthenticationAnalyzer(BaseAnalyzer):
    """Detect authentication-related phishing indicators."""

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze SPF, DKIM, and DMARC outcomes from email headers.

        Args:
            email: Email message to inspect

        Returns:
            List of authentication-related detection signals
        """
        auth_header = (email.headers.authentication_results or "").strip()
        if not auth_header:
            return [
                DetectionSignal(
                    signal_type="authentication",
                    confidence=0.35,
                    reason="Authentication-Results header is missing.",
                    severity="low",
                )
            ]

        signals: List[DetectionSignal] = []

        spf_result = self._extract_auth_result(auth_header, "spf")
        dkim_result = self._extract_auth_result(auth_header, "dkim")
        dmarc_result = self._extract_auth_result(auth_header, "dmarc")

        signals.extend(self._score_result("SPF", spf_result))
        signals.extend(self._score_result("DKIM", dkim_result))
        signals.extend(self._score_result("DMARC", dmarc_result))

        return signals

    @staticmethod
    def _extract_auth_result(auth_header: str, mechanism: str) -> Optional[str]:
        """Extract SPF/DKIM/DMARC result value from Authentication-Results."""
        pattern = rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z]+)"
        match = re.search(pattern, auth_header, re.IGNORECASE)
        if not match:
            return None
        return match.group(1).lower()

    @staticmethod
    def _score_result(mechanism: str, result: Optional[str]) -> List[DetectionSignal]:
        """Convert auth result into one or more detection signals."""
        if result is None:
            return [
                DetectionSignal(
                    signal_type="authentication",
                    confidence=0.45,
                    reason=f"{mechanism} result is missing from Authentication-Results.",
                    severity="medium",
                )
            ]

        if result == "pass":
            return []

        if result in {"fail", "permerror", "temperror"}:
            return [
                DetectionSignal(
                    signal_type="authentication",
                    confidence=0.9,
                    reason=f"{mechanism} check returned {result}.",
                    severity="high",
                )
            ]

        if result in {"softfail", "neutral", "none"}:
            return [
                DetectionSignal(
                    signal_type="authentication",
                    confidence=0.65,
                    reason=f"{mechanism} check returned {result}.",
                    severity="medium",
                )
            ]

        return [
            DetectionSignal(
                signal_type="authentication",
                confidence=0.5,
                reason=f"{mechanism} check returned unusual result: {result}.",
                severity="medium",
            )
        ]
