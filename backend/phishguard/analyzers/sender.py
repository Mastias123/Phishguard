"""Sender analyzer for impersonation and domain mismatch signals."""

from typing import List, Optional

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailMessage


class SenderAnalyzer(BaseAnalyzer):
    """Detect sender-related phishing indicators."""

    TRUSTED_BRAND_DOMAINS = {
        "mitid": {"mitid.dk", "mitid.nuuday.dk"},
        "github": {"github.com"},
        "microsoft": {"microsoft.com", "office.com", "outlook.com"},
        "apple": {"apple.com", "icloud.com"},
        "google": {"google.com", "gmail.com"},
        "paypal": {"paypal.com"},
        "amazon": {"amazon.com", "amazon.de", "amazon.co.uk"},
        "dhl": {"dhl.com"},
        "postnord": {"postnord.com", "postnord.dk"},
    }

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze sender name/address consistency and brand impersonation clues."""
        signals: List[DetectionSignal] = []
        all_auth_pass = self._all_auth_pass(email.headers.authentication_results)

        display_name = email.get_display_name().lower().strip()
        sender_domain = (email.sender_domain or "").lower().strip()

        if not sender_domain:
            signals.append(
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.6,
                    reason="Sender domain could not be extracted from From header.",
                    severity="medium",
                )
            )
            return signals

        # Brand impersonation check: display name contains a known brand but
        # sender domain is outside known domains for that brand.
        for brand, allowed_domains in self.TRUSTED_BRAND_DOMAINS.items():
            if brand in display_name and not self._domain_matches_any(sender_domain, allowed_domains):
                signals.append(
                    DetectionSignal(
                        signal_type="sender",
                        confidence=0.9,
                        reason=(
                            f"Display name references '{brand}' but sender domain "
                            f"is '{sender_domain}'."
                        ),
                        severity="high",
                    )
                )
                break

        # Basic suspicious TLD heuristic often seen in throwaway phishing domains.
        if sender_domain.endswith((".tk", ".top", ".xyz", ".click", ".work")):
            signals.append(
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.7,
                    reason=f"Sender domain uses a high-risk TLD: {sender_domain}.",
                    severity="medium",
                )
            )

        # Reply-To mismatch can indicate redirection to attacker mailbox.
        # Note: Auth passing (SPF/DKIM/DMARC) only proves authentic infrastructure,
        # not trustworthiness. An attacker can have a legitimate account.
        reply_to_domain = self._extract_domain(email.headers.reply_to)
        if reply_to_domain and reply_to_domain != sender_domain:
            signals.append(
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.65,
                    reason=(
                        f"Reply-To domain '{reply_to_domain}' does not match "
                        f"sender domain '{sender_domain}'."
                    ),
                    severity="medium",
                )
            )

        return signals

    @staticmethod
    def _extract_domain(addr: Optional[str]) -> Optional[str]:
        if not addr:
            return None
        value = addr.strip().lower()
        if "@" not in value:
            return None
        return value.split("@")[-1].rstrip(">")

    @staticmethod
    def _domain_matches_any(domain: str, candidates: set) -> bool:
        for candidate in candidates:
            if domain == candidate or domain.endswith("." + candidate):
                return True
        return False

    @staticmethod
    def _all_auth_pass(auth_header: Optional[str]) -> bool:
        if not auth_header:
            return False
        value = auth_header.lower()
        return "spf=pass" in value and "dkim=pass" in value and "dmarc=pass" in value
