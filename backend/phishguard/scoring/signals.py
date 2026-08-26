"""Risk scoring and analysis results."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class DetectionReason:
    """A reason contributing to the phishing score."""
    
    category: str  # "authentication", "sender", "url", "content", etc.
    severity: str  # "low", "medium", "high"
    reason: str  # Human-readable explanation
    confidence: float  # 0.0 to 1.0


@dataclass
class AnalysisResult:
    """Complete phishing analysis result for an email."""
    
    score: int  # 0-100, higher = more likely phishing
    reasons: List[DetectionReason] = field(default_factory=list)
    summary: str = ""
    
    def get_risk_level(self) -> str:
        """Get human-readable risk level."""
        if self.score >= 81:
            return "VERY HIGH RISK"
        elif self.score >= 61:
            return "HIGH RISK"
        elif self.score >= 41:
            return "MEDIUM RISK"
        elif self.score >= 21:
            return "LOW RISK"
        else:
            return "SAFE"
    
    def get_formatted_output(self) -> str:
        """Get formatted output for display."""
        output = f"{self.score} / 100 — {self.get_risk_level()}\n\n"
        
        if self.summary:
            output += f"{self.summary}\n\n"
        
        if self.reasons:
            output += "Reasons:\n"
            for reason in self.reasons:
                output += f"• {reason.reason}\n"
        
        return output
