"""Contextual link rules with phishing and legitimate-email counterexamples."""

from pathlib import Path
from typing import List

import pytest

from phishguard.analyzers.base import DetectionSignal
from phishguard.analyzers.domains import address_domain
from phishguard.analyzers.link_context import LinkContextAnalyzer
from phishguard.analyzers.organizations import OrganizationProfile
from phishguard.analyzers.sender import SenderAnalyzer
from phishguard.analyzers.url import URLAnalyzer
from phishguard.mail.models import EmailBody, EmailHeaders, EmailLink, EmailMessage
from phishguard.mail.parser import MimeParser


def _email(
    sender: str = "Skat Danmark <support@unrelated-example.com>",
    text: str = "Bekræft med MitID",
    destination: str = "https://abcd.zanuto.adv.br/verify",
    context: str = "",
    body: str = "",
) -> EmailMessage:
    return EmailMessage(
        headers=EmailHeaders(
            from_addr=sender,
            to_addrs=["recipient@example.net"],
            authentication_results="spf=pass; dkim=pass; dmarc=pass",
        ),
        body=EmailBody(text=body),
        sender_domain=address_domain(sender),
        links=[destination],
        link_details=[EmailLink(url=destination, text=text, context=context)],
    )


def _context(signals: List[DetectionSignal]) -> List[DetectionSignal]:
    return [signal for signal in signals if signal.signal_type == "link_context"]


@pytest.mark.parametrize("host", ["abcd.zanuto.adv.br", "refund-example.com", "refund-example.dk"])
def test_claimed_authority_and_unrelated_sensitive_destination_remain_strong(host: str) -> None:
    """Changing an attack to .com or .dk must not make it reassuring."""
    signals = URLAnalyzer().analyze(_email(destination=f"https://{host}/confirm"))

    assert len(_context(signals)) == 1
    assert _context(signals)[0].confidence == 0.95
    assert "Skattestyrelsen" in _context(signals)[0].reason
    assert not any(signal.signal_type == "url" for signal in signals)
    assert any(signal.signal_type == "geography" for signal in signals) == host.endswith(".br")


def test_real_skat_sample_retains_button_intent() -> None:
    """The supplied MIME sample should carry its visible MitID button into analysis."""
    sample = Path(__file__).resolve().parents[2] / "samples" / "skat_mail.eml"
    email = MimeParser.parse(sample.read_bytes())
    signals = URLAnalyzer().analyze(email)

    assert any(link.text == "Bekræft med MitID" for link in email.link_details)
    assert any(signal.severity == "high" for signal in _context(signals))
    assert any(signal.signal_type == "geography" for signal in signals)


@pytest.mark.parametrize("domain", ["skat.dk", "sktst.dk", "info.skat.dk"])
def test_official_domain_can_offer_mitid_action_without_mitid_in_url(domain: str) -> None:
    """Identity verification links may remain on the organization's own website."""
    email = _email(
        sender="Skattestyrelsen <service@sktst.dk>",
        destination=f"https://{domain}/borger",
    )

    assert URLAnalyzer().analyze(email) == []
    assert SenderAnalyzer().analyze(email) == []


def test_sensitive_link_on_attackers_sender_domain_still_conflicts_with_claim() -> None:
    """Sharing the sender's infrastructure does not establish the claimed identity."""
    signals = URLAnalyzer().analyze(
        _email(destination="https://unrelated-example.com/identity")
    )

    assert _context(signals)[0].confidence == 0.95


@pytest.mark.parametrize(
    "text,action",
    [
        ("Bekræft med MitID", "identity verification"),
        ("Verify your identity", "identity verification"),
        ("Bekræft din konto", "account access"),
        ("Log in", "account access"),
        ("Enter your password", "sensitive credentials"),
        ("Indtast din adgangskode", "sensitive credentials"),
        ("Pay your invoice", "payment"),
        ("Betal din faktura", "payment"),
    ],
)
def test_sensitive_actions_generalize_beyond_skat(text: str, action: str) -> None:
    """The same action rules apply to organizations across languages."""
    email = _email(sender="Microsoft Support <sender@unrelated-example.com>", text=text)
    signals = LinkContextAnalyzer().analyze(email)

    assert _context(signals)[0].confidence == 0.95
    assert action in _context(signals)[0].reason
    assert not any(signal.signal_type == "geography" for signal in signals)


@pytest.mark.parametrize("sender", ["Travel Club <travel@example.dk>", "Hotel <hello@hotel-example.com.br>"])
def test_brazilian_hotel_link_in_danish_travel_email_has_no_regional_penalty(sender: str) -> None:
    """Language and the .br suffix alone provide no regional impersonation evidence."""
    email = _email(
        sender=sender,
        text="Se hotellet",
        destination="https://hotel-example.com.br/photos",
        body="Din rejse til Brasilien er bekræftet. Læs om hotellet her.",
    )

    assert not _context(URLAnalyzer().analyze(email))
    assert not any(signal.signal_type == "geography" for signal in URLAnalyzer().analyze(email))


def test_unknown_sensitive_external_service_is_only_uncertainty() -> None:
    """Unfamiliar organizations and external services must not imply confirmed fraud."""
    signals = URLAnalyzer().analyze(
        _email(sender="Example Shop <orders@shop-example.dk>", text="Pay your invoice")
    )

    assert len(signals) == 1
    assert signals[0].signal_type == "link_context"
    assert signals[0].confidence == 0.35
    assert signals[0].severity == "low"


def test_known_sender_with_unconfigured_service_is_only_uncertainty() -> None:
    """A legitimate organization may use a service missing from our profiles."""
    signals = URLAnalyzer().analyze(_email(sender="Skat Danmark <service@skat.dk>"))

    assert len(signals) == 1
    assert signals[0].confidence == 0.35


def test_verified_external_payment_relationship_is_scoped_to_action() -> None:
    """Service domains need neither the sender's name nor the expected country suffix."""
    profile = OrganizationProfile(
        name="Example Shop",
        aliases=("Example Shop",),
        domains=("shop-example.dk",),
        country_codes=("dk",),
        action_domains={"payment": ("checkout-provider.com.br",)},
    )
    email = _email(
        sender="Example Shop <orders@shop-example.dk>",
        text="Pay your invoice",
        destination="https://checkout-provider.com.br/pay/123",
    )

    assert URLAnalyzer(profiles=(profile,)).analyze(email) == []
    assert SenderAnalyzer(profiles=(profile,)).analyze(email) == []

    email.link_details[0].text = "Enter your password"
    signals = URLAnalyzer(profiles=(profile,)).analyze(email)
    assert _context(signals)[0].confidence == 0.35


def test_verified_payment_redirect_can_display_the_shop_url() -> None:
    """An explicit scoped service relationship explains a displayed URL redirect."""
    profile = OrganizationProfile(
        "Example Shop", ("Example Shop",), ("shop-example.dk",),
        action_domains={"payment": ("checkout-provider.com",)},
    )
    email = _email(
        sender="Example Shop <orders@shop-example.dk>",
        text="https://shop-example.dk/invoice",
        destination="https://checkout-provider.com/pay",
        context="Pay your invoice using this link.",
    )

    assert URLAnalyzer(profiles=(profile,)).analyze(email) == []


@pytest.mark.parametrize("text", ["Read more", "Læs mere", "How to verify your identity", "Never enter your password"])
def test_security_advice_links_do_not_inherit_sensitive_actions(text: str) -> None:
    """Advice mentioning MitID is distinct from asking the recipient to authenticate."""
    email = _email(
        sender="Security News <news@example.dk>",
        text=text,
        body="Scammers say: Bekræft med MitID. Never enter your password.",
        context="Scammers ask you to verify your identity. Read the advice.",
    )

    assert not _context(URLAnalyzer().analyze(email))


def test_body_brand_mentions_do_not_establish_organization_claim() -> None:
    """Travel or advice content mentioning Skat must not establish sender identity."""
    signals = URLAnalyzer().analyze(
        _email(sender="Consultant <advice@example.dk>", body="A guide to Skat Danmark and MitID.")
    )

    assert _context(signals)[0].confidence == 0.35
    assert not any(signal.signal_type == "geography" for signal in signals)


@pytest.mark.parametrize("text,context", [
    ("Click here", "Verify your identity to continue."),
    ("Fortsæt", "Bekræft din identitet for at fortsætte."),
    ("Pay", "Pay your invoice using the following link."),
    ("Betal", "Betal din faktura via dette link."),
])
def test_generic_button_uses_local_action_context(text: str, context: str) -> None:
    """Generic buttons acquire meaning from their local explanation."""
    signals = URLAnalyzer().analyze(_email(text=text, context=context))

    assert _context(signals)[0].confidence == 0.95


def test_bare_url_with_negated_action_context_does_not_escalate() -> None:
    """A negative instruction near a URL is not a request to provide credentials."""
    destination = "https://guidance-example.com/article"
    email = _email(
        sender="Security News <news@example.dk>",
        text=destination,
        destination=destination,
        context="Never enter your password through links in emails.",
    )

    assert not _context(URLAnalyzer().analyze(email))


def test_sensitive_displayed_url_deception_does_not_require_known_sender() -> None:
    """A sensitive link that pretends to lead elsewhere is evidence by itself."""
    email = _email(
        sender="Accounts <mail@unrelated-example.com>",
        text="https://skat.dk/identity",
        context="Verify your identity to continue.",
    )

    assert _context(URLAnalyzer().analyze(email))[0].confidence == 0.95


def test_ordinary_newsletter_displayed_url_redirect_is_not_high_severity() -> None:
    """Ordinary displayed URL disagreement may be a legitimate tracking redirect."""
    email = _email(
        sender="Newsletter <news@shop-example.dk>",
        text="https://shop-example.dk/collection",
        destination="https://tracking.list-manage.com/click/123",
    )
    signals = URLAnalyzer().analyze(email)

    assert len(_context(signals)) == 1
    assert _context(signals)[0].confidence == 0.55
    assert _context(signals)[0].severity == "medium"


def test_repeated_buttons_do_not_multiply_destination_evidence() -> None:
    """Repeated and sibling-domain versions of one action yield stable findings."""
    email = _email()
    original = URLAnalyzer().analyze(email)
    email.link_details *= 5
    email.links *= 5
    email.link_details.append(
        EmailLink(url="https://other.zanuto.adv.br/again", text="Bekræft med MitID")
    )

    assert len(URLAnalyzer().analyze(email)) == len(original)
    assert [signal.confidence for signal in URLAnalyzer().analyze(email)] == [
        signal.confidence for signal in original
    ]


@pytest.mark.parametrize("sender", ["Appleton <contact@appleton.example>", "github@example.com"])
def test_sender_claims_require_display_name_word_boundaries(sender: str) -> None:
    """Brand substrings and email local parts are not display-name identity claims."""
    assert SenderAnalyzer().analyze(_email(sender=sender)) == []


def test_profile_domain_suffix_boundary_does_not_trust_lookalikes() -> None:
    """Containing a trusted domain in a different hostname does not establish ownership."""
    email = _email(
        sender="Skat Danmark <support@skat.dk.attacker-example.com>",
        destination="https://notskat.dk/identity",
    )

    assert SenderAnalyzer().analyze(email)[0].severity == "high"
    assert _context(URLAnalyzer().analyze(email))[0].confidence == 0.95


def test_sender_country_or_generic_suffix_alone_is_not_suspicious() -> None:
    """Suffixes have no meaning without supporting identity and action evidence."""
    assert SenderAnalyzer().analyze(_email(sender="Workshop <contact@example.work>")) == []


def test_sibling_sender_and_reply_to_domains_are_expected() -> None:
    """Domain comparisons treat ordinary sibling subdomains consistently."""
    email = _email(sender="Support <service@mail.example.dk>")
    email.headers.reply_to = "Support <help@support.example.dk>"

    assert SenderAnalyzer().analyze(email) == []


def test_legacy_url_list_remains_supported_without_link_metadata() -> None:
    """Old provider adapters retain weak domain checks without invented intent."""
    email = _email(sender="Shop <news@shop-example.dk>")
    email.link_details = []

    signals = URLAnalyzer().analyze(email)
    assert not _context(signals)
    assert all(signal.signal_type == "url" for signal in signals)


def test_authenticated_marketing_host_does_not_exempt_sensitive_impersonation() -> None:
    """Infrastructure authentication cannot justify an unrelated identity claim."""
    email = _email(destination="https://tracked.list-manage.com/verify")
    assert _context(URLAnalyzer().analyze(email))[0].confidence == 0.95
