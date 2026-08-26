"""Email provider base classes and interfaces."""

from abc import ABC, abstractmethod
from typing import List, Optional
from phishguard.mail.models import EmailMessage


class BaseProvider(ABC):
    """Abstract base class for email providers."""
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the email provider.
        
        Returns:
            True if authentication successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_mailbox_list(self) -> List[str]:
        """Get list of available mailboxes/folders.
        
        Returns:
            List of mailbox names
        """
        pass
    
    @abstractmethod
    def fetch_emails(
        self,
        mailbox: str = "INBOX",
        limit: Optional[int] = None,
        unread_only: bool = False
    ) -> List[EmailMessage]:
        """Fetch emails from specified mailbox.
        
        Args:
            mailbox: Mailbox/folder name
            limit: Maximum number of emails to fetch
            unread_only: Only fetch unread emails
            
        Returns:
            List of EmailMessage objects
        """
        pass
    
    @abstractmethod
    def fetch_email_by_id(self, email_id: str, mailbox: str = "INBOX") -> Optional[EmailMessage]:
        """Fetch a specific email by ID.
        
        Args:
            email_id: Email ID/UID
            mailbox: Mailbox/folder name
            
        Returns:
            EmailMessage or None if not found
        """
        pass
    
    @abstractmethod
    def close(self):
        """Close connection to email provider."""
        pass
