"""End-to-end regression pairs for contextual phishing assessment."""

from pathlib import Path
from typing import Optional

import pytest

from phishguard.analyzers.authentication import AuthenticationAnalyzer
from phishguard.analyzers.content import ContentAnalyzer
from phishguard.analyzers.sender import SenderAnalyzer
from phishguard.analyzers.url import URLAnalyzer
from phishguard.mail.parser import MimeParser
from phishguard.scoring.scorer import RiskScorer
from phishguard.scoring.signals import AnalysisResult

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def analyze_message(mime: bytes) -> AnalysisResult:
    """Run a raw message through the same analyzers as the CLI.

    Args:
        mime: Raw MIME email bytes.

    Returns:
        Complete risk assessment.
    """
    return RiskScorer(
        [AuthenticationAnalyzer(), SenderAnalyzer(), URLAnalyzer(), ContentAnalyzer()]
    ).score(MimeParser.parse(mime))


@pytest.mark.parametrize("suffix", ["br", "com", "dk"])
def test_skat_sample_stays_high_risk_with_generic_or_local_destination(suffix: str) -> None:
    """Country suffix changes cannot erase identity/action/destination evidence."""
    mime = (SAMPLES / "skat_mail.eml").read_bytes()
    if suffix != "br":
        mime = mime.replace(b"abcd.zanuto.adv.br", f"unrelated-checkout.{suffix}".encode())
    result = analyze_message(mime)
    assert result.score >= 61
    assert any(reason.category == "link_context" and reason.severity == "high" for reason in result.reasons)
    assert any(reason.category == "sender" for reason in result.reasons)
    assert any(reason.category == "geography" for reason in result.reasons) == (suffix == "br")
    assert not any(
        reason.category == "url" and "does not match sender" in reason.reason
        for reason in result.reasons
    )


def test_repeating_the_skat_button_does_not_change_score() -> None:
    """Repeated copies retain the same underlying evidence and score."""
    mime = (SAMPLES / "skat_mail.eml").read_bytes()
    button = (
        '<p><a href="https://abcd.zanuto.adv.br/url/digital/">'
        "Bekræft med MitID</a></p>"
    ).encode()
    duplicated = mime.replace(b"</body>", button * 20 + b"</body>")
    assert analyze_message(duplicated).score == analyze_message(mime).score


@pytest.mark.parametrize(
    "label,body",
    [
        ("Se hotellet", "Dit hotel i Brasilien er klar til dit besøg."),
        ("View hotel", "Your hotel in Brazil is ready for your visit."),
    ],
)
def test_legitimate_brazilian_travel_link_in_different_languages(label: str, body: str) -> None:
    """A Danish sender linking to a Brazilian hotel has no regional penalty."""
    mime = (
        'From: "Travel Desk" <booking@travel.example>\n'
        "To: user@example.com\n"
        "Subject: Your itinerary\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        f'<p>{body}</p><p><a href="https://hotel.com.br/rooms">{label}</a></p>'
    ).encode()
    result = analyze_message(mime)
    assert result.score <= 20
    assert not any(reason.category in {"link_context", "geography"} for reason in result.reasons)


@pytest.mark.parametrize("suffix", ["br", "com", "dk"])
def test_unknown_organization_external_login_stays_uncertain(suffix: str) -> None:
    """An unknown external service is not treated as confirmed impersonation."""
    mime = (
        'From: "Neighborhood Club" <support@club.example>\n'
        "To: user@example.com\n"
        "Subject: Membership portal\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        f'<a href="https://member-service.{suffix}/">Sign in</a>'
    ).encode()
    result = analyze_message(mime)
    assert result.score < 41
    context = [reason for reason in result.reasons if reason.category == "link_context"]
    assert len(context) == 1
    assert context[0].confidence < 0.5
    assert not any(reason.category == "geography" for reason in result.reasons)


@pytest.mark.parametrize("authentication", [None, "spf=pass; dkim=pass; dmarc=pass"])
def test_authentication_cannot_remove_contextual_identity_evidence(
    authentication: Optional[str],
) -> None:
    """Passing authentication for an unrelated sender does not establish brand identity."""
    mime = (
        'From: "Skat Danmark" <support@unrelated.example>\n'
        "To: user@example.com\n"
        "Subject: Identity confirmation\n"
        + (f"Authentication-Results: {authentication}\n" if authentication else "")
        + "Content-Type: text/html; charset=utf-8\n\n"
        + '<a href="https://unrelated-checkout.com/">Bekræft med MitID</a>'
    ).encode()
    result = analyze_message(mime)
    assert result.score >= 61
    assert any(reason.category == "link_context" and reason.severity == "high" for reason in result.reasons)
