"""Phishing detection analyzers."""

from phishguard.analyzers.base import BaseAnalyzer, DetectionSignal
from phishguard.analyzers.authentication import AuthenticationAnalyzer
from phishguard.analyzers.sender import SenderAnalyzer
from phishguard.analyzers.url import URLAnalyzer

__all__ = [
    "BaseAnalyzer",
    "DetectionSignal",
    "AuthenticationAnalyzer",
    "SenderAnalyzer",
    "URLAnalyzer",
]
