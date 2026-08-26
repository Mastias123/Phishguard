"""Phishing detection analyzers."""

from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass
from phishguard.mail.models import EmailMessage


@dataclass
class DetectionSignal:
    """A detected signal indicating potential phishing."""
    
    signal_type: str  # "authentication", "sender", "url", "content", etc.
    confidence: float  # 0.0 to 1.0
    reason: str  # Human-readable explanation
    severity: str  # "low", "medium", "high"


class BaseAnalyzer(ABC):
    """Abstract base class for email analyzers."""
    
    @abstractmethod
    def analyze(self, email: EmailMessage) -> List[DetectionSignal]:
        """Analyze an email for phishing indicators.
        
        Args:
            email: EmailMessage to analyze
            
        Returns:
            List of DetectionSignal objects found
        """
        pass
