"""Compare sensitive link actions with claimed identities and destinations."""

import re
import unicodedata
from typing import Dict, List, Optional, Sequence, Tuple

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.analyzers.domains import (
    address_domain,
    country_suffix,
    domain_matches,
    registrable_domain,
    same_domain,
    url_host,
)
from phishguard.analyzers.organizations import (
    DEFAULT_ORGANIZATION_PROFILES,
    OrganizationProfile,
    claimed_organization,
)
from phishguard.mail.models import EmailLink, EmailMessage


class LinkContextAnalyzer(BaseAnalyzer):
    """Detect inconsistent identity, action, and destination evidence.

    English and Danish action phrases are deliberately narrow. A brand mention,
    unfamiliar destination, or country suffix alone is not strong evidence.
    """

    ACTION_PATTERNS: Tuple[Tuple[str, str], ...] = (
        (
            "identity",
            r"\b(?:verify|confirm|validate)\s+(?:(?:your|the)\s+)?identity\b"
            r"|\b(?:verify|confirm|authenticate)\s+(?:with|using)\s+mitid\b"
            r"|\b(?:bekræft|verificer|godkend)\s+(?:(?:din|jeres)\s+)?identitet\b"
            r"|\b(?:bekræft|verificer|godkend)\s+(?:med|via)\s+mitid\b"
            r"|\bidentitetsbekræftelse\b",
        ),
        (
            "credentials",
            r"\b(?:enter|provide|submit|update|reset|confirm)\s+(?:(?:your|the)\s+)?"
            r"(?:password|passphrase|pin|security\s+code|verification\s+code|card\s+details)\b"
            r"|\b(?:indtast|angiv|oplys|opdater|nulstil|bekræft)\s+(?:(?:din|dit|dine)\s+)?"
            r"(?:adgangskode|kodeord|pinkode|sikkerhedskode|kortoplysninger)\b",
        ),
        (
            "login",
            r"\b(?:log\s*in|sign\s*in)\b"
            r"|\b(?:verify|confirm|reactivate)\s+(?:(?:your|the)\s+)?account\b"
            r"|\b(?:bekræft|verificer|genaktiver)\s+(?:(?:din|jeres)\s+)?konto\b",
        ),
        (
            "payment",
            r"\b(?:pay|settle)\s+(?:(?:your|the|this)\s+)?(?:invoice|bill|fee|balance)\b"
            r"|\b(?:pay\s+now|make\s+(?:a\s+)?payment|update\s+(?:your\s+)?payment)\b"
            r"|\b(?:betal|godkend)\s+(?:(?:din|dit|denne|en)\s+)?"
            r"(?:faktura|regning|gebyr|betaling)\b"
            r"|\b(?:betal\s+nu|opdater\s+(?:dine\s+)?betalingsoplysninger)\b",
        ),
    )
    ACTION_DESCRIPTIONS = {
        "identity": "identity verification",
        "credentials": "sensitive credentials",
        "login": "account access",
        "payment": "payment",
    }
    GENERIC_ACTION_TEXT = re.compile(
        r"^(?:click\s+(?:here|below)|continue|proceed|verify|confirm|"
        r"klik\s+(?:her|nedenfor)|fortsæt|bekræft|pay|betal)(?:\s+(?:now|nu))?[.!: ]*$"
    )
    ADVICE_TEXT = re.compile(
        r"\b(?:never|do\s+not|don't|avoid|beware|learn\s+how|how\s+to|"
        r"aldrig|undgå|pas\s+på|lær\s+at)\b"
        r"|\b(?:skal|bør|må)\s+(?:du\s+)?ikke\b"
    )

    def __init__(self, profiles: Optional[Sequence[OrganizationProfile]] = None) -> None:
        """Initialize the analyzer with default or caller-supplied profiles.

        Args:
            profiles: Explicit identities and service relationships. An empty
                sequence disables organization-specific claims.
        """
        self.profiles = tuple(DEFAULT_ORGANIZATION_PROFILES if profiles is None else profiles)

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Find contextual contradictions, capped at one finding per domain.

        Args:
            email: Message with visible link text and local context.

        Returns:
            Strong or modest link findings and optional secondary geography clues.
        """
        profile = claimed_organization(email, self.profiles)
        sender = email.sender_domain or address_domain(email.headers.from_addr)
        findings: Dict[str, DetectionSignal] = {}
        geography: Dict[str, DetectionSignal] = {}

        for link in email.link_details:
            host = url_host(link.url)
            if not host:
                continue
            group = "destination:" + registrable_domain(host)
            action = self._sensitive_action(link)
            displayed_host = self._displayed_host(link.text)
            misleading = bool(displayed_host and not same_domain(displayed_host, host))
            expected = (
                profile.allows_destination(host, action)
                if profile
                else bool(sender and same_domain(host, sender))
            )
            sender_outside_claim = bool(profile and not domain_matches(sender, profile.domains))
            verified_redirect = bool(
                profile
                and profile.allows_destination(displayed_host)
                and profile.allows_destination(host, action)
            )

            signal: Optional[DetectionSignal] = None
            if misleading and not verified_redirect:
                sensitive_mismatch = bool(action and not (profile and expected))
                signal = DetectionSignal(
                    signal_type="link_context",
                    confidence=0.95 if sensitive_mismatch else 0.55,
                    reason=(
                        f"Displayed link URL names '{displayed_host}', but its destination is "
                        f"'{host}'."
                        + (
                            " The link requests a sensitive action without an established "
                            "relationship to the displayed domain."
                            if sensitive_mismatch
                            else " This may be a legitimate redirect."
                        )
                    ),
                    severity="high" if sensitive_mismatch else "medium",
                    evidence_group=group,
                )
            elif action and not expected:
                description = self.ACTION_DESCRIPTIONS[action]
                if profile and sender_outside_claim:
                    signal = DetectionSignal(
                        signal_type="link_context",
                        confidence=0.95,
                        reason=(
                            f"Email claims to be {profile.name} and requests {description}, "
                            f"but neither sender '{sender}' nor destination '{host}' has "
                            "an established connection to that organization for this action."
                        ),
                        severity="high",
                        evidence_group=group,
                    )
                else:
                    signal = DetectionSignal(
                        signal_type="link_context",
                        confidence=0.35,
                        reason=(
                            f"Link requests {description} at '{host}'; no relationship "
                            "with the sender is established. An external service may be legitimate."
                        ),
                        severity="low",
                        evidence_group=group,
                    )

            if signal:
                previous = findings.get(group)
                if previous is None or signal.confidence > previous.confidence:
                    findings[group] = signal

            # Regional inconsistency only supports an already strong identity/action finding.
            destination_country = country_suffix(host)
            if (
                action
                and profile
                and sender_outside_claim
                and not expected
                and destination_country
                and profile.country_codes
                and destination_country not in profile.country_codes
            ):
                geography[group] = DetectionSignal(
                    signal_type="geography",
                    confidence=0.5,
                    reason=(
                        f"The '.{destination_country}' destination suffix also differs from "
                        f"the configured regional context for {profile.name} "
                        f"({', '.join(profile.country_codes)}). This is supporting evidence only."
                    ),
                    severity="low",
                    evidence_group="geography:" + registrable_domain(host),
                )

        return list(findings.values()) + list(geography.values())

    @classmethod
    def _sensitive_action(cls, link: EmailLink) -> Optional[str]:
        text = cls._normalize_text(link.text)
        action = cls._match_action(text)
        if action:
            return action

        # Context may explain an otherwise generic button or a bare URL. An ordinary
        # "Read more" link must not inherit a sensitive action elsewhere in the email.
        if not text or cls._displayed_host(text) or cls.GENERIC_ACTION_TEXT.fullmatch(text):
            return cls._match_action(cls._normalize_text(link.context))
        return None

    @classmethod
    def _match_action(cls, text: str) -> Optional[str]:
        # Restrict negative/advisory interpretation to the sentence containing the action.
        for sentence in re.split(r"[.!?;\n]+", text):
            if cls.ADVICE_TEXT.search(sentence):
                continue
            for action, pattern in cls.ACTION_PATTERNS:
                if re.search(pattern, sentence):
                    return action
        return None

    @staticmethod
    def _normalize_text(text: str) -> str:
        return " ".join(unicodedata.normalize("NFC", text).casefold().split())

    @staticmethod
    def _displayed_host(text: str) -> str:
        displayed = text.strip()
        if not displayed or re.search(r"\s", displayed):
            return ""
        candidate = displayed if "://" in displayed else "https://" + displayed
        host = url_host(candidate)
        if "." not in host or "@" in displayed:
            return ""
        return host if registrable_domain(host) else ""
