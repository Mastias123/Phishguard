"""MIME message parsing and header extraction."""

import email
from email.message import Message
from typing import Optional, List, Dict
from phishguard.mail.models import EmailMessage, EmailHeaders, EmailBody, EmailAttachment


class MimeParser:
    """Parses MIME messages into normalized EmailMessage objects."""
    
    @staticmethod
    def parse(mime_content: str, provider: str = "unknown") -> EmailMessage:
        """Parse a MIME message string into an EmailMessage.
        
        Args:
            mime_content: Raw MIME message content
            provider: Source provider name (for reference)
            
        Returns:
            Normalized EmailMessage object
        """
        msg = email.message_from_string(mime_content)
        
        # Extract headers
        headers = MimeParser._extract_headers(msg)
        
        # Extract body
        body = MimeParser._extract_body(msg)
        
        # Extract attachments
        attachments = MimeParser._extract_attachments(msg)
        
        # Create email message
        email_msg = EmailMessage(
            headers=headers,
            body=body,
            provider=provider,
            attachments=attachments,
            message_id=msg.get("Message-ID"),
        )
        
        # Extract links (TODO: implement link extraction from HTML)
        email_msg.links = MimeParser._extract_links(body)
        
        # Extract domains from sender info
        email_msg.sender_domain = MimeParser._extract_domain_from_email(headers.from_addr)
        email_msg.display_name_domain = MimeParser._extract_domain_from_display_name(headers.from_addr)
        
        return email_msg
    
    @staticmethod
    def _extract_headers(msg: Message) -> EmailHeaders:
        """Extract and structure email headers."""
        from_addr = msg.get("From", "")
        to = msg.get("To", "").split(",") if msg.get("To") else []
        cc = msg.get("Cc", "").split(",") if msg.get("Cc") else []
        
        # Parse date
        date_str = msg.get("Date")
        date = None
        if date_str:
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(date_str)
            except (TypeError, ValueError):
                pass
        
        # Get authentication results
        auth_results = msg.get("Authentication-Results")
        received = msg.get_all("Received") or []
        dkim_sig = msg.get("DKIM-Signature")
        
        return EmailHeaders(
            from_addr=from_addr,
            to_addrs=[t.strip() for t in to if t.strip()],
            cc_addrs=[c.strip() for c in cc if c.strip()],
            subject=msg.get("Subject", ""),
            date=date,
            reply_to=msg.get("Reply-To"),
            return_path=msg.get("Return-Path"),
            message_id=msg.get("Message-ID"),
            authentication_results=auth_results,
            received=received,
            dkim_signature=dkim_sig,
            raw_headers=dict(msg.items()),
        )
    
    @staticmethod
    def _extract_body(msg: Message) -> EmailBody:
        """Extract text and HTML body from message."""
        text_part = None
        html_part = None
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not text_part:
                    text_part = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == "text/html" and not html_part:
                    html_part = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            
            if content_type == "text/plain":
                text_part = payload
            elif content_type == "text/html":
                html_part = payload
        
        return EmailBody(text=text_part, html=html_part)
    
    @staticmethod
    def _extract_attachments(msg: Message) -> List[EmailAttachment]:
        """Extract attachment metadata."""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename() or "unknown"
                    content_type = part.get_content_type()
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    
                    attachments.append(EmailAttachment(
                        filename=filename,
                        content_type=content_type,
                        size=size,
                        is_inline=False,
                    ))
        
        return attachments
    
    @staticmethod
    def _extract_links(body: EmailBody) -> List[str]:
        """Extract URLs from email body."""
        import re
        
        links = []
        url_pattern = r'https?://[^\s\)<>\[\]"\'`]+'
        
        content = body.get_content()
        if content:
            matches = re.findall(url_pattern, content)
            links.extend(matches)
        
        return links
    
    @staticmethod
    def _extract_domain_from_email(email_addr: str) -> Optional[str]:
        """Extract domain from email address."""
        if '@' in email_addr:
            domain = email_addr.split('@')[1].rstrip('>')
            return domain
        return None
    
    @staticmethod
    def _extract_domain_from_display_name(from_header: str) -> Optional[str]:
        """Extract domain mentioned in display name."""
        import re
        
        # Remove email part if present
        if '<' in from_header:
            display_name = from_header.split('<')[0].strip().strip('"')
        else:
            display_name = from_header
        
        # Look for domain-like patterns in display name
        domain_pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        matches = re.findall(domain_pattern, display_name)
        
        if matches:
            return matches[0]
        
        return None
