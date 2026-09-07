"""Risk scoring engine."""

from typing import List
from phishguard.mail.models import EmailMessage
from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.scoring.signals import AnalysisResult, DetectionReason


class RiskScorer:
    """Combines analyzer signals into a final phishing risk score."""
    
    # Signal weights (higher = more important)
    SIGNAL_WEIGHTS = {
        "authentication": 0.25,  # SPF/DKIM/DMARC
        "sender": 0.20,          # Domain mismatch, impersonation
        "url": 0.30,             # Suspicious URLs
        "content": 0.15,         # Urgency language, password requests
        "attachment": 0.10,      # Suspicious attachments
        "link_context": 0.50,    # Combined action, identity, and destination evidence
        "geography": 0.05,       # Weak supporting context, capped at 2.5 points
    }

    # One contextual destination cannot be amplified by copying it or adding more links.
    STRONGEST_ONLY_CATEGORIES = {"link_context", "geography"}
    CONTRIBUTION_CAPS = {"geography": 2.5}
    
    def __init__(self, analyzers: List[BaseAnalyzer]):
        """Initialize scorer with list of analyzers.
        
        Args:
            analyzers: List of BaseAnalyzer implementations
        """
        self.analyzers = analyzers
    
    def score(self, email: EmailMessage) -> AnalysisResult:
        """Score an email for phishing risk.
        
        Args:
            email: EmailMessage to score
            
        Returns:
            AnalysisResult with score and reasons
        """
        all_signals: List[DetectionSignal] = []
        
        # Collect signals from all analyzers
        for analyzer in self.analyzers:
            signals = analyzer.analyze(email)
            all_signals.extend(signals)

        all_signals = self._select_independent_signals(all_signals)
        
        # Convert signals to reasons
        reasons: List[DetectionReason] = []
        total_score = 0.0
        
        for signal in all_signals:
            reasons.append(DetectionReason(
                category=signal.signal_type,
                severity=signal.severity,
                reason=signal.reason,
                confidence=signal.confidence,
            ))
            
            # Weight the signal
            signal_contribution = self._signal_contribution(signal)
            total_score += signal_contribution
        
        # Normalize score to 0-100 range
        final_score = min(int(total_score), 100)
        
        # Create summary
        summary = self._create_summary(final_score, reasons)
        
        return AnalysisResult(
            score=final_score,
            reasons=reasons,
            summary=summary,
        )

    @classmethod
    def _signal_contribution(cls, signal: DetectionSignal) -> float:
        weight = cls.SIGNAL_WEIGHTS.get(signal.signal_type, 0.1)
        contribution = signal.confidence * weight * 100
        return min(contribution, cls.CONTRIBUTION_CAPS.get(signal.signal_type, 100.0))

    @classmethod
    def _select_independent_signals(
        cls, signals: List[DetectionSignal]
    ) -> List[DetectionSignal]:
        """Keep the strongest finding per evidence group and capped category."""
        grouped = {}
        for index, signal in enumerate(signals):
            key = ("evidence", signal.evidence_group) if signal.evidence_group else ("signal", index)
            previous = grouped.get(key)
            if previous is None or cls._signal_contribution(signal) > cls._signal_contribution(previous):
                grouped[key] = signal

        selected = {}
        for index, signal in enumerate(grouped.values()):
            key = ("category", signal.signal_type) if signal.signal_type in cls.STRONGEST_ONLY_CATEGORIES else ("signal", index)
            previous = selected.get(key)
            if previous is None or cls._signal_contribution(signal) > cls._signal_contribution(previous):
                selected[key] = signal
        return list(selected.values())
    
    @staticmethod
    def _create_summary(score: int, reasons: List[DetectionReason]) -> str:
        """Create a summary based on score."""
        if score >= 81:
            return "This email shows strong indicators of being a phishing attempt. Be very cautious."
        elif score >= 61:
            return "This email has suspicious characteristics typical of phishing emails."
        elif score >= 41:
            return "This email has some characteristics that warrant caution."
        elif score >= 21:
            return "This email has some minor indicators that it may not be legitimate."
        else:
            return "This email appears to be legitimate."
