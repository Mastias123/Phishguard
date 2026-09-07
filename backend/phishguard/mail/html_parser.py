"""Extract visible HTML text and link context without loading remote resources."""

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from phishguard.mail.models import EmailLink

_BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
}
_VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
_HIDDEN_TAGS = {"head", "script", "style", "template"}
_URL_PATTERN = re.compile(r"https?://[^\s<>\[\]\"'`]+", re.IGNORECASE)
_CONTEXT_LIMIT = 500


def _clean_text(value: str) -> str:
    return " ".join(value.split())


def _nearby_context(content: str, start: int, end: int) -> str:
    """Keep context in the link's paragraph and bound its size around the label."""
    previous_boundary = content.rfind("\n\n", 0, start)
    paragraph_start = 0 if previous_boundary < 0 else previous_boundary + 2
    paragraph_end = content.find("\n\n", end)
    if paragraph_end < 0:
        paragraph_end = len(content)
    window_start = max(paragraph_start, start - _CONTEXT_LIMIT // 2)
    window_end = min(paragraph_end, window_start + _CONTEXT_LIMIT)
    window_start = max(paragraph_start, window_end - _CONTEXT_LIMIT)
    return _clean_text(content[window_start:window_end])


def extract_plain_links(content: str) -> List[EmailLink]:
    """Extract HTTP(S) URLs and bounded paragraph context from visible text.

    Args:
        content: Plain body text or visible text extracted from HTML.

    Returns:
        Links with their literal URL as the label and nearby paragraph text.
    """
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    links = []
    for match in _URL_PATTERN.finditer(content):
        url = match.group().rstrip(".,;!")
        while url.endswith(")") and url.count(")") > url.count("("):
            url = url[:-1]
        links.append(
            EmailLink(
                url=url,
                text=url,
                context=_nearby_context(content, match.start(), match.start() + len(url)),
            )
        )
    return links


@dataclass
class _Scope:
    start: int
    end: Optional[int] = None


@dataclass
class _Anchor:
    url: str
    start: int
    scope: _Scope
    end: Optional[int] = None


@dataclass
class _Frame:
    tag: str
    hidden: bool
    scope: Optional[_Scope] = None
    anchor: Optional[_Anchor] = None


class _VisibleHTMLParser(HTMLParser):
    """Record text offsets so even deeply nested markup needs no recursive walk."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: List[str] = []
        self.length = 0
        self.root_scope = _Scope(0)
        self.stack: List[_Frame] = [_Frame("", False, self.root_scope)]
        self.anchors: List[_Anchor] = []

    def _append(self, value: str) -> None:
        self.chunks.append(value)
        self.length += len(value)

    def _close_from(self, index: int) -> None:
        for frame in reversed(self.stack[index:]):
            if frame.anchor is not None:
                frame.anchor.end = self.length
            if frame.scope is not None:
                frame.scope.end = self.length
        del self.stack[index:]

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """Record visible block boundaries, image labels and anchor destinations."""
        # Common optional end tags should not swallow following paragraphs/cells.
        close_tags = {"p"} if tag in _BLOCK_TAGS else set()
        if tag in {"li", "tr", "a"}:
            close_tags.add(tag)
        if tag in {"td", "th"}:
            close_tags.update({"td", "th"})
        scope_boundaries = {
            "li": {"ul", "ol"},
            "tr": {"table"},
            "td": {"tr", "table"},
            "th": {"tr", "table"},
        }.get(tag, set())
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag in close_tags:
                self._close_from(index)
                break
            if self.stack[index].tag in scope_boundaries:
                break

        attributes = dict(attrs)
        style = re.sub(r"\s+", "", attributes.get("style") or "").lower()
        hidden = (
            self.stack[-1].hidden
            or tag in _HIDDEN_TAGS
            or "hidden" in attributes
            or re.search(r"(?:^|;)display:none(?:!important)?(?:;|$)", style) is not None
            or re.search(r"(?:^|;)visibility:(?:hidden|collapse)(?:!important)?(?:;|$)", style)
            is not None
        )
        if not hidden and tag in _BLOCK_TAGS:
            self._append("\n\n")
        if not hidden and tag == "br":
            self._append("\n")
        if not hidden and tag == "img" and attributes.get("alt"):
            self._append(" " + (attributes["alt"] or "") + " ")

        scope = _Scope(self.length) if tag in _BLOCK_TAGS else None
        anchor = None
        if tag == "a" and not hidden:
            url = (attributes.get("href") or "").strip()
            if url.startswith("//"):
                url = "https:" + url
            try:
                parsed_url = urlsplit(url)
                is_web_url = parsed_url.scheme.lower() in {"http", "https"} and bool(
                    parsed_url.hostname
                )
            except ValueError:
                is_web_url = False
            if is_web_url:
                parent_scope = next(
                    frame.scope for frame in reversed(self.stack) if frame.scope is not None
                )
                anchor = _Anchor(url, self.length, parent_scope)
                self.anchors.append(anchor)
        if tag not in _VOID_TAGS:
            self.stack.append(_Frame(tag, hidden, scope, anchor))

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """Handle self-closing elements without leaving a hidden scope open."""
        self.handle_starttag(tag, attrs)
        if tag not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        """Close matching scopes, tolerating missing and mismatched end tags."""
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                visible = not self.stack[index].hidden
                self._close_from(index)
                if visible and tag in _BLOCK_TAGS:
                    self._append("\n\n")
                return

    def handle_data(self, data: str) -> None:
        """Retain decoded text only when the current element is visible."""
        if not self.stack[-1].hidden:
            # HTML source line breaks are whitespace, unlike explicit block boundaries.
            self._append(re.sub(r"\s+", " ", data))

    def extract(self) -> Tuple[str, List[EmailLink]]:
        """Finalize open scopes and return visible text and contextual links."""
        self._close_from(1)
        self.root_scope.end = self.length
        content = "".join(self.chunks)
        links = []
        for anchor in self.anchors:
            anchor_start = anchor.start
            scope_start = anchor.scope.start
            end = anchor.end if anchor.end is not None else self.length
            scope_end = anchor.scope.end if anchor.scope.end is not None else self.length
            context = content[scope_start:scope_end]
            links.append(
                EmailLink(
                    url=anchor.url,
                    text=_clean_text(content[anchor_start:end]),
                    context=_nearby_context(
                        context, anchor.start - anchor.scope.start, end - anchor.scope.start
                    ),
                )
            )
        # Text that looks like a URL inside an anchor is its label, not another
        # destination. Excluding it preserves deceptive label/target relationships.
        for match in _URL_PATTERN.finditer(content):
            if any(
                anchor.start <= match.start() < (anchor.end or self.length)
                for anchor in self.anchors
            ):
                continue
            plain_links = extract_plain_links(match.group())
            if plain_links:
                link = plain_links[0]
                link.context = _nearby_context(content, match.start(), match.end())
                links.append(link)
        paragraphs = [_clean_text(part) for part in content.split("\n\n")]
        return "\n\n".join(part for part in paragraphs if part), links


def extract_html_content(content: str) -> Tuple[str, List[EmailLink]]:
    """Extract visible text and HTTP(S) links using local HTML parsing only.

    Args:
        content: Decoded HTML body. External stylesheets and resources are not loaded.

    Returns:
        Visible text and links with labels and at most 500 characters of context.
        Explicit hidden attributes and inline display/visibility styles are excluded;
        arbitrary CSS layout and stylesheet rules are not evaluated.
    """
    parser = _VisibleHTMLParser()
    parser.feed(content)
    parser.close()
    return parser.extract()
