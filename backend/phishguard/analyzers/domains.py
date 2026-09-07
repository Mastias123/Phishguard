"""Normalize and compare domains using an offline Public Suffix List snapshot."""

from email.utils import parseaddr
from ipaddress import ip_address
from typing import Iterable, Optional
from urllib.parse import urlsplit

import idna
import tldextract

# Include private suffixes so different tenants on github.io remain unrelated.
# No network request or user-cache write is needed when analyzing an email.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def normalize_host(host: str) -> str:
    """Return a canonical IP address or IDNA hostname, or empty for invalid input.

    Args:
        host: Hostname without a scheme, path, or port.

    Returns:
        Lowercase ASCII hostname or canonical IP address.
    """
    value = host.strip().rstrip(".")
    if not value:
        return ""
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    try:
        return idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError:
        return ""


def registrable_domain(host: str) -> str:
    """Return the registrable domain, preserving unknown suffixes and IP addresses.

    Args:
        host: Hostname to normalize and inspect.

    Returns:
        Registrable domain, or the complete host when no PSL boundary is known.
    """
    normalized = normalize_host(host)
    if not normalized:
        return ""
    extracted = _EXTRACT(normalized)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return normalized


def same_domain(first: str, second: str) -> bool:
    """Check whether two nonempty hosts share a registrable domain.

    Args:
        first: First host to compare.
        second: Second host to compare.

    Returns:
        Whether both valid hosts share the same registrable domain.
    """
    first_domain = registrable_domain(first)
    return bool(first_domain and first_domain == registrable_domain(second))


def domain_matches(host: str, candidates: Iterable[str]) -> bool:
    """Match configured domains on exact names or whole subdomain boundaries.

    Args:
        host: Host to check.
        candidates: Explicitly configured organizational or service domains.

    Returns:
        Whether the host equals or is below a configured domain.
    """
    normalized = normalize_host(host)
    if not normalized:
        return False
    for candidate in candidates:
        allowed = normalize_host(candidate)
        if allowed and (normalized == allowed or normalized.endswith("." + allowed)):
            return True
    return False


def url_host(url: str) -> str:
    """Extract a validated host from an HTTP(S) or protocol-relative URL.

    Args:
        url: Link destination to inspect without fetching it.

    Returns:
        Canonical host, or empty when the URL is malformed or unsupported.
    """
    try:
        parsed = urlsplit("https:" + url if url.startswith("//") else url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        # Accessing port also validates malformed/out-of-range port numbers.
        _ = parsed.port
        return normalize_host(parsed.hostname or "")
    except ValueError:
        return ""


def country_suffix(host: str) -> Optional[str]:
    """Return a recognized two-letter top-level suffix as contextual evidence.

    Args:
        host: Hostname to inspect.

    Returns:
        Country-code suffix, or None for generic, unknown, or invalid suffixes.
        This does not establish the host's physical location or ownership.
    """
    normalized = normalize_host(host)
    if not normalized:
        return None
    suffix = _EXTRACT(normalized).suffix
    top_level = suffix.rsplit(".", 1)[-1]
    return top_level if len(top_level) == 2 and top_level.isalpha() else None


def address_domain(address: Optional[str]) -> str:
    """Extract a canonical domain from an email address or display-name header.

    Args:
        address: Email address, optionally with a display name.

    Returns:
        Canonical domain, or empty when the address has no valid domain.
    """
    mailbox = parseaddr(address or "")[1]
    if "@" not in mailbox:
        return ""
    return normalize_host(mailbox.rsplit("@", 1)[1])
