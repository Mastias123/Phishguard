"""
PhishGuard - Provider-independent phishing detection system for emails

A modular system for analyzing emails from multiple providers and detecting
phishing attempts with explainable risk scores.
"""

__version__ = "0.1.0"
__author__ = "PhishGuard Contributors"
__license__ = "MIT"

from phishguard.mail.models import EmailMessage, EmailHeaders
from phishguard.scoring.signals import AnalysisResult

__all__ = [
    "EmailMessage",
    "EmailHeaders",
    "AnalysisResult",
]
