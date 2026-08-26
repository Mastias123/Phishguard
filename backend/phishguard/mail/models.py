"""Core email message models."""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class EmailHeaders:
    """Structured email headers."""
    
    from_addr: str
    to_addrs: List[str]
    cc_addrs: List[str] = field(default_factory=list)
    bcc_addrs: List[str] = field(default_factory=list)
    subject: str = ""
    date: Optional[datetime] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    
    # Authentication and routing
    authentication_results: Optional[str] = None
    received: List[str] = field(default_factory=list)
    dkim_signature: Optional[str] = None
    
    # Raw headers (for reference)
    raw_headers: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmailBody:
    """Email message body (text and HTML variants)."""
    
    text: Optional[str] = None
    html: Optional[str] = None
    
    def get_content(self) -> str:
        """Get best available content (prefers HTML converted to text)."""
        return self.text or self.html or ""


@dataclass
class EmailAttachment:
    """Email attachment metadata."""
    
    filename: str
    content_type: str
    size: int
    is_inline: bool = False


@dataclass
class EmailMessage:
    """Normalized email message model.
    
    This is the canonical representation used throughout PhishGuard,
    regardless of which provider the email came from.
    """
    
    # Core message data
    headers: EmailHeaders
    body: EmailBody
    
    # Message metadata
    message_id: Optional[str] = None
    provider: str = "unknown"  # "imap", "microsoft_graph", etc.
    folder: str = "INBOX"
    is_read: bool = False
    
    # Attachments
    attachments: List[EmailAttachment] = field(default_factory=list)
    
    # Extracted data (populated by parsers/analyzers)
    links: List[str] = field(default_factory=list)
    display_name_domain: Optional[str] = None
    sender_domain: Optional[str] = None
    
    def get_sender_email(self) -> str:
        """Extract email address from From header."""
        return self.headers.from_addr
    
    def get_display_name(self) -> str:
        """Extract display name from From header if present."""
        from_header = self.headers.from_addr
        if '<' in from_header:
            return from_header.split('<')[0].strip().strip('"')
        return from_header
