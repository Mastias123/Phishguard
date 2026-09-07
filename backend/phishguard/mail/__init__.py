"""Email model and parsing module."""

from phishguard.mail.models import EmailBody, EmailHeaders, EmailLink, EmailMessage

__all__ = [
    "EmailMessage",
    "EmailHeaders",
    "EmailBody",
    "EmailLink",
]
