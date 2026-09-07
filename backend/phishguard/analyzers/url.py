"""URL analysis combining link intent, identity, and destination evidence."""

from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.analyzers.domains import (
    address_domain,
    domain_matches,
    registrable_domain,
    same_domain,
    url_host,
)
from phishguard.analyzers.link_context import LinkContextAnalyzer
from phishguard.analyzers.organizations import (
    DEFAULT_ORGANIZATION_PROFILES,
    OrganizationProfile,
    claimed_organization,
)
from phishguard.mail.models import EmailMessage


class URLAnalyzer(BaseAnalyzer):
    """Inspect web links without requiring sender names in their domains."""

    SUSPICIOUS_HOST_KEYWORDS = {
        "verify", "update", "secure", "account", "login", "signin", "confirm"
    }
    TRACKING_REDIRECT_HOSTS = {"zohoinsights.com", "sendgrid.net"}
    MARKETING_INFRA_HOSTS = {
        "list-manage.com", "mailchimp.com", "mailchimpapp.com", "mailchimpapp.net",
        "login.mailchimp.com", "mcdlv.net", "bloomreach.com",
    }

    def __init__(self, profiles: Optional[Sequence[OrganizationProfile]] = None) -> None:
        """Initialize contextual URL analysis with configurable relationships.

        Args:
            profiles: Known organizations and action-specific external services.
                None uses defaults; an empty sequence disables organization claims.
        """
        self.profiles = tuple(DEFAULT_ORGANIZATION_PROFILES if profiles is None else profiles)
        self._context_analyzer = LinkContextAnalyzer(self.profiles)

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze normalized URLs and visible link text together.

        Args:
            email: Message with legacy URL strings and optional link details.

        Returns:
            Deduplicated contextual and generic URL findings.
        """
        signals = self._context_analyzer.analyze(email)
        contextual_groups = {
            signal.evidence_group for signal in signals if signal.signal_type == "link_context"
        }
        sender_domain = email.sender_domain or address_domain(email.headers.from_addr)
        profile = claimed_organization(email, self.profiles)
        all_auth_pass = self._all_auth_pass(email.headers.authentication_results)
        details_by_url = {}
        for detail in email.link_details:
            details_by_url.setdefault(detail.url, []).append(detail)

        links = list(dict.fromkeys(email.links + [detail.url for detail in email.link_details]))
        mismatch_hosts: List[str] = []
        for link in links:
            host = url_host(link)
            if not host:
                continue
            group = "destination:" + registrable_domain(host)
            try:
                scheme = urlsplit(link).scheme.lower()
            except ValueError:
                continue
            if scheme == "http":
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=0.5,
                        reason=f"Link uses unencrypted HTTP: {link}",
                        severity="low",
                        evidence_group="transport:" + registrable_domain(host),
                    )
                )

            # Context already explains this destination; do not repeat the same
            # mismatch through generic domain, keyword, and redirect rules.
            if group in contextual_groups:
                continue

            expected = bool(sender_domain and same_domain(host, sender_domain))
            if profile:
                expected = expected or profile.allows_destination(host)
                expected = expected or any(
                    profile.allows_destination(host, self._context_analyzer._sensitive_action(detail))
                    for detail in details_by_url.get(link, [])
                )
            if expected or self._is_expected_marketing_infra(host, all_auth_pass):
                continue

            # An unfamiliar external domain is weak evidence: legitimate emails
            # regularly link to other organizations and service providers.
            if sender_domain:
                mismatch_hosts.append(host)

            if self._contains_keyword(host):
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=0.3,
                        reason=(
                            "Unestablished external link host contains an account/action word: "
                            f"{host}."
                        ),
                        severity="low",
                        evidence_group=group,
                    )
                )

            if domain_matches(host, self.TRACKING_REDIRECT_HOSTS):
                signals.append(
                    DetectionSignal(
                        signal_type="url",
                        confidence=0.15,
                        reason=f"External link uses a tracking/redirect host: {host}.",
                        severity="low",
                        evidence_group=group,
                    )
                )

        signals.extend(self._build_mismatch_signals(mismatch_hosts, sender_domain))
        return self._deduplicate(signals)

    @classmethod
    def _contains_keyword(cls, host: str) -> bool:
        return any(keyword in host for keyword in cls.SUSPICIOUS_HOST_KEYWORDS)

    @staticmethod
    def _domain_matches_any(domain: str, candidates: Iterable[str]) -> bool:
        return domain_matches(domain, candidates)

    @staticmethod
    def _same_organization_domain(host: str, sender_domain: str) -> bool:
        return same_domain(host, sender_domain)

    @classmethod
    def _is_expected_marketing_infra(cls, host: str, all_auth_pass: bool) -> bool:
        return all_auth_pass and domain_matches(host, cls.MARKETING_INFRA_HOSTS)

    @staticmethod
    def _registrable_domain(domain: str) -> str:
        return registrable_domain(domain)

    @staticmethod
    def _deduplicate(signals: List[DetectionSignal]) -> List[DetectionSignal]:
        strongest = {}
        for signal in signals:
            key = signal.evidence_group or (signal.signal_type, signal.reason)
            previous = strongest.get(key)
            if previous is None or signal.confidence > previous.confidence:
                strongest[key] = signal
        return list(strongest.values())

    @classmethod
    def _build_mismatch_signals(
        cls, mismatch_hosts: List[str], sender_domain: str
    ) -> List[DetectionSignal]:
        unique_hosts = {}
        for host in mismatch_hosts:
            unique_hosts.setdefault(registrable_domain(host), host)
        return [
            DetectionSignal(
                signal_type="url",
                confidence=0.15,
                reason=(
                    f"Link host '{host}' does not match sender domain '{sender_domain}'; "
                    "external links are common in legitimate email."
                ),
                severity="low",
                evidence_group="destination:" + domain,
            )
            for domain, host in list(unique_hosts.items())[:3]
        ]

    @staticmethod
    def _all_auth_pass(auth_header: Optional[str]) -> bool:
        if not auth_header:
            return False
        value = auth_header.lower()
        return "spf=pass" in value and "dkim=pass" in value and "dmarc=pass" in value
