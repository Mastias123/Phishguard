"""Related link evidence must not inflate risk through repetition."""

from typing import List

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.mail.models import EmailBody, EmailHeaders, EmailMessage
from phishguard.scoring.scorer import RiskScorer


class FixedAnalyzer(BaseAnalyzer):
    """Return controlled evidence to exercise score aggregation."""

    def __init__(self, signals: List[DetectionSignal]) -> None:
        """Store the evidence returned by this analyzer.

        Args:
            signals: Findings to return during scoring.
        """
        self.signals = signals

    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Return the configured evidence.

        Args:
            email: Message supplied by the scoring pipeline.

        Returns:
            Configured findings.
        """
        return self.signals


def test_repeated_and_overlapping_link_evidence_uses_strongest() -> None:
    """A contextual finding replaces a weaker finding on the same destination."""
    email = EmailMessage(EmailHeaders("sender@example.com", []), EmailBody())
    generic = DetectionSignal("url", 0.15, "External link", "low", "destination:evil.com")
    context = DetectionSignal(
        "link_context", 0.95, "Identity deception", "high", "destination:evil.com"
    )
    region = DetectionSignal(
        "geography", 0.5, "Regional inconsistency", "low", "geography:evil.com"
    )
    original = RiskScorer([FixedAnalyzer([generic, context, region])]).score(email)
    repeated = RiskScorer([FixedAnalyzer([generic, context, region] * 10)]).score(email)
    assert original.score == repeated.score == 50
    assert [reason.reason for reason in repeated.reasons] == [
        "Identity deception", "Regional inconsistency"
    ]


def test_many_destinations_do_not_stack_contextual_or_geographic_risk() -> None:
    """The strongest destination controls the contextual score across a message."""
    email = EmailMessage(EmailHeaders("sender@example.com", []), EmailBody())
    signals = [
        DetectionSignal("link_context", 0.95, "Deceptive action", "high", "destination:first.br"),
        DetectionSignal("link_context", 0.35, "Unknown relationship", "medium", "destination:two.br"),
        DetectionSignal("geography", 0.5, "Region one", "low", "geography:first.br"),
        DetectionSignal("geography", 0.9, "Region two", "low", "geography:two.br"),
    ]
    result = RiskScorer([FixedAnalyzer(signals)]).score(email)
    assert result.score == 50
    assert len(result.reasons) == 2


def test_independent_sender_and_authentication_evidence_still_counts() -> None:
    """Caps for contextual links retain independent identity/authentication findings."""
    email = EmailMessage(EmailHeaders("sender@example.com", []), EmailBody())
    signals = [
        DetectionSignal("link_context", 0.95, "Deceptive action", "high", "destination:evil.com"),
        DetectionSignal("sender", 0.9, "Impersonation", "high"),
        DetectionSignal("authentication", 0.65, "DMARC none", "medium"),
    ]
    result = RiskScorer([FixedAnalyzer(signals)]).score(email)
    assert result.score == 81
    assert result.get_risk_level() == "VERY HIGH RISK"
