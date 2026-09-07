"""Explicit organization identities and scoped service relationships.

These profiles are evidence for comparisons, not a general trust allowlist.
New external service domains should be added only after verifying the relationship.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Mapping, Optional, Sequence, Tuple

from phishguard.analyzers.domains import domain_matches
from phishguard.mail.models import EmailMessage


@dataclass(frozen=True)
class OrganizationProfile:
    """Known identity, domains, and optional action-specific service domains.

    Attributes:
        name: Organization name shown in findings.
        aliases: Names used when identifying a claim in the sender display name.
        domains: Verified organization domains, including their subdomains.
        country_codes: Expected country suffixes, if the organization is regional.
        action_domains: Verified external services scoped to identity, login,
            payment, or credentials actions. These do not authorize sender domains.
    """

    name: str
    aliases: Tuple[str, ...]
    domains: Tuple[str, ...]
    country_codes: Tuple[str, ...] = ()
    action_domains: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    def allows_destination(self, host: str, action: Optional[str] = None) -> bool:
        """Check a destination against organization and scoped service domains.

        Args:
            host: Destination hostname.
            action: Sensitive action category, or None for an ordinary link.

        Returns:
            Whether the profile contains the destination relationship.
        """
        service_domains = self.action_domains.get(action, ()) if action else ()
        return domain_matches(host, self.domains + tuple(service_domains))


DEFAULT_ORGANIZATION_PROFILES: Tuple[OrganizationProfile, ...] = (
    OrganizationProfile(
        name="Skattestyrelsen",
        aliases=("Skat Danmark", "Skattestyrelsen", "SKAT"),
        domains=("skat.dk", "sktst.dk"),
        country_codes=("dk",),
    ),
    OrganizationProfile("MitID", ("MitID",), ("mitid.dk", "mitid.nuuday.dk"), ("dk",)),
    OrganizationProfile("GitHub", ("GitHub",), ("github.com",)),
    OrganizationProfile(
        "Microsoft", ("Microsoft",), ("microsoft.com", "office.com", "outlook.com")
    ),
    OrganizationProfile("Apple", ("Apple",), ("apple.com", "icloud.com")),
    OrganizationProfile("Google", ("Google",), ("google.com", "gmail.com")),
    OrganizationProfile("PayPal", ("PayPal",), ("paypal.com",)),
    OrganizationProfile("Amazon", ("Amazon",), ("amazon.com", "amazon.de", "amazon.co.uk")),
    OrganizationProfile("DHL", ("DHL",), ("dhl.com",)),
    OrganizationProfile("PostNord", ("PostNord",), ("postnord.com", "postnord.dk")),
)


def claimed_organization(
    email: EmailMessage, profiles: Sequence[OrganizationProfile]
) -> Optional[OrganizationProfile]:
    """Find an organization named in the sender's display name.

    Body mentions and an address's local part do not establish identity claims.
    Alias matching uses complete words rather than substrings, so a name such as
    Appleton does not claim to be Apple.

    Args:
        email: Message containing the From header.
        profiles: Organization identities to compare.

    Returns:
        First matching profile, or None when no claim is established.
    """
    display_name = parseaddr(email.headers.from_addr)[0]
    normalized = unicodedata.normalize("NFC", display_name).casefold()
    normalized = " ".join(normalized.split())
    for profile in profiles:
        for alias in profile.aliases:
            phrase = " ".join(unicodedata.normalize("NFC", alias).casefold().split())
            if phrase and re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", normalized):
                return profile
    return None
