"""URL analyzer for suspicious link indicators."""

from typing import List
from urllib.parse import urlparse

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailMessage


class URLAnalyzer(BaseAnalyzer):
    """Detect suspicious patterns in links embedded in emails."""

    SUSPICIOUS_HOST_KEYWORDS = {
        "verify",
        "update",
        "secure",
        "account",
        "login",
        "signin",
        "confirm",
    }

    TRACKING_REDIRECT_HOSTS = {
        "zohoinsights.com",
        "mailchimp.com",
        "sendgrid.net",
    }

    MARKETING_INFRA_HOSTS = {
        "list-manage.com",
        "mailchimpapp.com",
        "mailchimpapp.net",
        "mcdlv.net",
        "bloomreach.com",
    }

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze extracted links for phishing indicators."""
        signals: List[DetectionSignal] = []
        sender_domain = (email.sender_domain or "").lower().strip()
        all_auth_pass = self._all_auth_pass(email.headers.authentication_results)
        mismatch_hosts: List[str] = []

        if not email.links:
            return signals

        for link in email.links:
            parsed = urlparse(link)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()

            if scheme != "https":
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=0.7,
                        reason=f"Link uses non-HTTPS scheme: {link}",
                        severity="medium",
                    )
                )

            if host and sender_domain and not self._same_organization_domain(host, sender_domain):
                if not self._is_expected_marketing_infra(host, all_auth_pass):
                    mismatch_hosts.append(host)

            if self._contains_keyword(host) and not self._is_expected_marketing_infra(host, all_auth_pass):
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=0.55,
                        reason=f"Link host contains phishing-style keyword: {host}",
                        severity="medium",
                    )
                )

            if self._domain_matches_any(host, self.TRACKING_REDIRECT_HOSTS):
                confidence = 0.35 if all_auth_pass else 0.6
                severity = "low" if all_auth_pass else "medium"
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=confidence,
                        reason=f"Link uses a known tracking/redirect host: {host}.",
                        severity=severity,
                    )
                )

        signals.extend(self._build_mismatch_signals(mismatch_hosts, sender_domain, all_auth_pass))

        return self._deduplicate(signals)

    @classmethod
    def _contains_keyword(cls, host: str) -> bool:
        return any(keyword in host for keyword in cls.SUSPICIOUS_HOST_KEYWORDS)

    @staticmethod
    def _domain_matches_any(domain: str, candidates: set) -> bool:
        for candidate in candidates:
            if domain == candidate or domain.endswith("." + candidate):
                return True
        return False

    @classmethod
    def _same_organization_domain(cls, host: str, sender_domain: str) -> bool:
        """Compare domains on registrable/base domain to avoid subdomain false positives."""
        return cls._registrable_domain(host) == cls._registrable_domain(sender_domain)

    @classmethod
    def _is_expected_marketing_infra(cls, host: str, all_auth_pass: bool) -> bool:
        if not all_auth_pass:
            return False
        return cls._domain_matches_any(host, cls.MARKETING_INFRA_HOSTS)

    @staticmethod
    def _registrable_domain(domain: str) -> str:
        """Extract a best-effort registrable domain (e.g. a.b.example.com -> example.com)."""
        labels = [label for label in domain.lower().split(".") if label]
        if len(labels) < 2:
            return domain.lower()

        # Handle common second-level structures like co.uk/com.au.
        common_second_level = {"co", "com", "org", "net", "gov", "ac", "edu"}
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in common_second_level:
            return ".".join(labels[-3:])

        return ".".join(labels[-2:])

    @staticmethod
    def _deduplicate(signals: List[DetectionSignal]) -> List[DetectionSignal]:
        seen = set()
        unique: List[DetectionSignal] = []
        for signal in signals:
            key = (signal.signal_type, signal.reason)
            if key in seen:
                continue
            seen.add(key)
            unique.append(signal)
        return unique

    @classmethod
    def _build_mismatch_signals(
        cls,
        mismatch_hosts: List[str],
        sender_domain: str,
        all_auth_pass: bool,
    ) -> List[DetectionSignal]:
        """Build capped mismatch signals to avoid over-penalizing bulk marketing emails."""
        unique_hosts: List[str] = []
        seen_reg_domains = set()
        for host in mismatch_hosts:
            reg = cls._registrable_domain(host)
            if reg in seen_reg_domains:
                continue
            seen_reg_domains.add(reg)
            unique_hosts.append(host)

        max_signals = 1 if all_auth_pass else 3
        confidence = 0.45 if all_auth_pass else 0.85
        severity = "low" if all_auth_pass else "high"

        signals: List[DetectionSignal] = []
        for host in unique_hosts[:max_signals]:
            signals.append(
                DetectionSignal(
                    signal_type="url",
                    confidence=confidence,
                    reason=(
                        f"Link host '{host}' does not match sender domain "
                        f"'{sender_domain}'."
                    ),
                    severity=severity,
                )
            )
        return signals

    @staticmethod
    def _all_auth_pass(auth_header: str) -> bool:
        if not auth_header:
            return False
        value = auth_header.lower()
        return "spf=pass" in value and "dkim=pass" in value and "dmarc=pass" in value
