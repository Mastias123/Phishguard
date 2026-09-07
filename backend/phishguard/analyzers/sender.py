"""Sender analyzer for impersonation and domain mismatch signals."""

from typing import List, Optional, Sequence

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.analyzers.domains import address_domain, domain_matches, same_domain
from phishguard.analyzers.organizations import (
    DEFAULT_ORGANIZATION_PROFILES,
    OrganizationProfile,
    claimed_organization,
)
from phishguard.mail.models import EmailMessage


class SenderAnalyzer(BaseAnalyzer):
    """Compare sender identity claims with explicitly configured domains."""

    def __init__(self, profiles: Optional[Sequence[OrganizationProfile]] = None) -> None:
        """Initialize default or caller-supplied organization identities.

        Args:
            profiles: Known organizations. An empty sequence disables brand checks.
        """
        self.profiles = tuple(DEFAULT_ORGANIZATION_PROFILES if profiles is None else profiles)

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze sender name, domain, and Reply-To consistency.

        Args:
            email: Normalized message to inspect.

        Returns:
            Sender evidence; suffixes alone never establish impersonation.
        """
        signals: List[DetectionSignal] = []
        sender_domain = email.sender_domain or address_domain(email.headers.from_addr)

        if not sender_domain:
            return [
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.6,
                    reason="Sender domain could not be extracted from From header.",
                    severity="medium",
                )
            ]

        profile = claimed_organization(email, self.profiles)
        if profile and not domain_matches(sender_domain, profile.domains):
            signals.append(
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.9,
                    reason=(
                        f"Display name claims '{profile.name}', but sender domain "
                        f"'{sender_domain}' is outside its configured organization domains."
                    ),
                    severity="high",
                    evidence_group="sender_identity",
                )
            )

        # Auth passing establishes infrastructure, not an organization's identity.
        # Compare registered domains so legitimate sibling mail domains do not conflict.
        reply_to_domain = address_domain(email.headers.reply_to)
        if reply_to_domain and not same_domain(reply_to_domain, sender_domain):
            signals.append(
                DetectionSignal(
                    signal_type="sender",
                    confidence=0.65,
                    reason=(
                        f"Reply-To domain '{reply_to_domain}' does not match "
                        f"sender domain '{sender_domain}'."
                    ),
                    severity="medium",
                    evidence_group="reply_to",
                )
            )

        return signals
