"""MIME message parsing and header extraction."""

import email
import re
from email.header import decode_header
from email.message import Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Dict, Iterator, List, Optional, Tuple, Union

from phishguard.mail.html_parser import extract_html_content, extract_plain_links
from phishguard.mail.models import (
    EmailAttachment,
    EmailBody,
    EmailHeaders,
    EmailLink,
    EmailMessage,
)


class MimeParser:
    """Parse MIME messages into provider-independent email models."""

    @staticmethod
    def parse(mime_content: Union[str, bytes], provider: str = "unknown") -> EmailMessage:
        """Parse a MIME message and preserve visible link labels and local context.

        Args:
            mime_content: Raw MIME bytes (preferred) or an already decoded MIME string.
            provider: Source provider name for reference.

        Returns:
            Normalized email with decoded headers, both body variants, and links.
        """
        if isinstance(mime_content, bytes):
            msg = email.message_from_bytes(mime_content)
        else:
            msg = email.message_from_string(mime_content)

        headers = MimeParser._extract_headers(msg)
        body, link_details = MimeParser._extract_body_and_links(
            msg, already_decoded=isinstance(mime_content, str)
        )
        return EmailMessage(
            headers=headers,
            body=body,
            provider=provider,
            attachments=MimeParser._extract_attachments(msg),
            message_id=headers.message_id,
            links=list(dict.fromkeys(link.url for link in link_details)),
            link_details=link_details,
            sender_domain=MimeParser._extract_domain_from_email(headers.from_addr),
            display_name_domain=MimeParser._extract_domain_from_display_name(headers.from_addr),
        )

    @staticmethod
    def _decode_bytes(payload: bytes, charset: Optional[str] = None) -> str:
        """Respect the declared encoding, with deterministic fallbacks for broken MIME."""
        for encoding in dict.fromkeys([charset or "utf-8", "utf-8", "windows-1252"]):
            try:
                return payload.decode(encoding)
            except (LookupError, UnicodeError):
                continue
        return payload.decode("utf-8", errors="replace")

    @staticmethod
    def _decode_header(value: object) -> str:
        """Decode RFC 2047 words while preserving display-name quoting."""
        if value is None:
            return ""
        result = []
        try:
            chunks = decode_header(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            chunks = [(str(value), None)]
        for chunk, charset in chunks:
            if isinstance(chunk, bytes):
                result.append(MimeParser._decode_bytes(chunk, charset))
            else:
                # BytesParser may retain non-ASCII raw headers as surrogate escapes.
                result.append(
                    MimeParser._decode_bytes(chunk.encode("utf-8", errors="surrogateescape"))
                )
        return "".join(result)

    @staticmethod
    def _extract_headers(msg: Message) -> EmailHeaders:
        """Extract decoded structured headers and retain all routing headers."""
        decoded: Dict[str, str] = {}
        for key, value in msg.raw_items():
            # Preserve Message.get's first-header behavior for identity and auth.
            decoded.setdefault(key.lower(), MimeParser._decode_header(value))

        def addresses(name: str) -> List[str]:
            return [
                address
                for _, address in getaddresses(
                    [MimeParser._decode_header(value) for value in msg.get_all(name, [])]
                )
                if address
            ]

        date = None
        if decoded.get("date"):
            try:
                date = parsedate_to_datetime(decoded["date"])
            except (TypeError, ValueError, OverflowError):
                pass
        return EmailHeaders(
            from_addr=decoded.get("from", ""),
            to_addrs=addresses("To"),
            cc_addrs=addresses("Cc"),
            bcc_addrs=addresses("Bcc"),
            subject=decoded.get("subject", ""),
            date=date,
            reply_to=decoded.get("reply-to"),
            return_path=decoded.get("return-path"),
            message_id=decoded.get("message-id"),
            authentication_results=decoded.get("authentication-results"),
            received=[MimeParser._decode_header(value) for value in msg.get_all("Received", [])],
            dkim_signature=decoded.get("dkim-signature"),
            raw_headers={key: MimeParser._decode_header(value) for key, value in msg.raw_items()},
        )

    @staticmethod
    def _body_parts(msg: Message) -> Iterator[Message]:
        """Walk visible MIME body parts without descending into attached messages."""
        pending = [msg]
        while pending:
            part = pending.pop()
            if (
                part.get_content_disposition() == "attachment"
                or part.get_filename() is not None
                or part.get_content_maintype() == "message"
            ):
                continue
            payload = part.get_payload()
            if part.is_multipart() and isinstance(payload, list):
                pending.extend(reversed(payload))
            elif part.get_content_type() in {"text/plain", "text/html"}:
                yield part

    @staticmethod
    def _decode_part(part: Message, already_decoded: bool = False) -> str:
        """Decode transfer encoding and the charset of a single body part."""
        raw_payload = part.get_payload()
        transfer_encoding = str(part.get("Content-Transfer-Encoding", "")).lower()
        if (
            already_decoded
            and isinstance(raw_payload, str)
            and transfer_encoding not in {"base64", "quoted-printable"}
            and any(ord(character) > 127 for character in raw_payload)
            and not any(0xD800 <= ord(character) <= 0xDFFF for character in raw_payload)
        ):
            # Unicode MIME strings may already be decoded. Keep them intact.
            return raw_payload
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return MimeParser._decode_bytes(payload, part.get_content_charset())
        return raw_payload if isinstance(raw_payload, str) else ""

    @staticmethod
    def _extract_body_and_links(
        msg: Message, already_decoded: bool = False
    ) -> Tuple[EmailBody, List[EmailLink]]:
        """Collect all body alternatives and deduplicate identical contextual links."""
        text_parts = []
        html_parts = []
        visible_parts = []
        link_details = []
        for part in MimeParser._body_parts(msg):
            content = MimeParser._decode_part(part, already_decoded)
            if part.get_content_type() == "text/html":
                html_parts.append(content)
                visible, links = extract_html_content(content)
            else:
                text_parts.append(content)
                visible, links = content, extract_plain_links(content)
            if visible.strip():
                visible_parts.append(visible.strip())
            link_details.extend(links)

        seen = set()
        unique_links = []
        for link in link_details:
            key = (link.url, link.text, link.context)
            if key not in seen:
                seen.add(key)
                unique_links.append(link)
        return (
            EmailBody(
                text="\n\n".join(text_parts) if text_parts else None,
                html="\n\n".join(html_parts) if html_parts else None,
                visible_text="\n\n".join(dict.fromkeys(visible_parts)),
            ),
            unique_links,
        )

    @staticmethod
    def _extract_attachments(msg: Message) -> List[EmailAttachment]:
        """Extract attachment metadata, without treating attached MIME as body text."""
        attachments = []
        pending = [msg]
        while pending:
            part = pending.pop()
            if (
                part.get_content_disposition() == "attachment"
                or part.get_filename() is not None
                or part.get_content_maintype() == "message"
            ):
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    size = len(payload)
                elif part.is_multipart():
                    size = sum(len(child.as_bytes()) for child in part.get_payload())
                else:
                    size = 0
                attachments.append(
                    EmailAttachment(
                        filename=MimeParser._decode_header(part.get_filename() or "unknown"),
                        content_type=part.get_content_type(),
                        size=size,
                        is_inline=part.get_content_disposition() == "inline",
                    )
                )
                continue
            payload = part.get_payload()
            if part.is_multipart() and isinstance(payload, list):
                pending.extend(reversed(payload))
        return attachments

    @staticmethod
    def _extract_domain_from_email(email_addr: str) -> Optional[str]:
        """Extract the sender's domain without confusing an at sign in its label."""
        address = parseaddr(email_addr)[1]
        return address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else None

    @staticmethod
    def _extract_domain_from_display_name(from_header: str) -> Optional[str]:
        """Extract an explicitly displayed domain, excluding ordinary brand words."""
        display_name = parseaddr(from_header)[0]
        match = re.search(
            r"(?<![\w@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" r"[a-z]{2,63}(?![\w-])",
            display_name,
            re.IGNORECASE,
        )
        return match.group().lower() if match else None
