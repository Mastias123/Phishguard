"""Regression coverage for visible content and contextual links in MIME messages."""

from email.message import EmailMessage as MimeMessage
from pathlib import Path

import pytest
from phishguard.mail.models import EmailBody
from phishguard.mail.parser import MimeParser


def _html_mail(body: str) -> bytes:
    message = MimeMessage()
    message["From"] = "Example <sender@example.com>"
    message["To"] = "person@example.net"
    message.set_content(body, subtype="html")
    return message.as_bytes()


def test_html_links_preserve_entities_nested_labels_and_image_alt() -> None:
    """Buttons retain meaningful labels, including labels represented by an image."""
    parsed = MimeParser.parse(
        _html_mail(
            '<p>Din identitet: <a href="https://unrelated.test/?a=1&amp;b=2">'
            "<span>Bekr&aelig;ft <strong>med MitID</strong></span></a></p>"
            '<p><a href="//payments.example.com/pay">'
            '<img src="https://images.example.com/pay.png" alt="Pay your invoice"></a></p>'
        )
    )

    assert parsed.links == [
        "https://unrelated.test/?a=1&b=2",
        "https://payments.example.com/pay",
    ]
    assert parsed.link_details[0].text == "Bekræft med MitID"
    assert parsed.link_details[0].context == "Din identitet: Bekræft med MitID"
    assert parsed.link_details[1].text == "Pay your invoice"
    assert "<span>" not in parsed.body.get_content()


def test_visible_content_excludes_styles_scripts_and_explicitly_hidden_elements() -> None:
    """Invisible preheaders and resource URLs do not masquerade as reader actions."""
    parsed = MimeParser.parse(
        _html_mail(
            "<head><title>Hidden title</title><style>.x {display:block}</style></head>"
            '<script>location = "https://script.test";</script>'
            '<div hidden><a href="https://hidden.test">Verify hidden identity</a></div>'
            '<p style="DISPLAY: none !important;">Hidden CSS text</p>'
            '<p style="visibility: hidden">Hidden visibility</p>'
            '<template><a href="https://template.test">Hidden template</a></template>'
            '<p>Hello &amp; welcome. <a href="https://visible.test">Read more</a></p>'
        )
    )

    assert parsed.body.get_content() == "Hello & welcome. Read more"
    assert parsed.links == ["https://visible.test"]


def test_multipart_alternatives_keep_html_only_actions_and_context_variants() -> None:
    """A harmless plain-text alternative cannot hide an actionable HTML destination."""
    message = MimeMessage()
    message.set_content("Read our update at https://example.com/update")
    message.add_alternative(
        '<p><a href="https://example.com/update">Read our update</a></p>'
        '<p><a href="https://unrelated.test/verify">Confirm your identity</a></p>',
        subtype="html",
    )

    parsed = MimeParser.parse(message.as_bytes())

    assert parsed.links == ["https://example.com/update", "https://unrelated.test/verify"]
    assert len(parsed.link_details) == 3
    assert "Confirm your identity" in parsed.body.get_content()
    assert parsed.body.text is not None
    assert parsed.body.html is not None


def test_attachment_bodies_and_forwarded_messages_are_excluded() -> None:
    """Attached text/HTML and embedded messages cannot contribute body-link evidence."""
    message = MimeMessage()
    message.set_content("See https://body.example.com")
    message.add_attachment("https://attachment.test", filename="notes.txt")
    message.add_attachment(
        b'<a href="https://html-attachment.test">Confirm your password</a>',
        maintype="text",
        subtype="html",
        filename="attachment.html",
        disposition="inline",
    )
    forwarded = MimeMessage()
    forwarded.set_content("https://forwarded.test")
    message.add_attachment(forwarded)

    parsed = MimeParser.parse(message.as_bytes())

    assert parsed.links == ["https://body.example.com"]
    assert "attachment.test" not in parsed.body.get_content()
    assert "forwarded.test" not in parsed.body.get_content()
    assert len(parsed.attachments) == 3
    assert parsed.attachments[1].is_inline
    assert parsed.attachments[2].size > 0


@pytest.mark.parametrize("charset", ["utf-8", "iso-8859-1", "windows-1252"])
def test_declared_body_charsets_and_encoded_headers(charset: str) -> None:
    """MIME header and payload decoding preserve Danish action words."""
    message = MimeMessage()
    message["From"] = '"Skattestyrelsen Øst" <noreply@example.dk>'
    message["Subject"] = "Bekræft din identitet 🔔"
    message["To"] = '"Doe, Jane" <jane@example.com>, john@example.com'
    message.set_content(
        '<p><a href="https://unrelated.test">Bekræft med MitID</a></p>',
        subtype="html",
        charset=charset,
    )

    parsed = MimeParser.parse(message.as_bytes())

    assert parsed.headers.subject == "Bekræft din identitet 🔔"
    assert "Skattestyrelsen Øst" in parsed.headers.from_addr
    assert parsed.headers.to_addrs == ["jane@example.com", "john@example.com"]
    assert parsed.link_details[0].text == "Bekræft med MitID"


def test_unknown_charset_falls_back_without_discarding_action_words() -> None:
    """A broken charset declaration does not silently remove non-ASCII evidence."""
    raw = (
        b"Content-Type: text/html; charset=nonexistent\n\n"
        + '<p><a href="https://unrelated.test">Bekræft med MitID</a></p>'.encode("utf-8")
    )

    assert MimeParser.parse(raw).link_details[0].text == "Bekræft med MitID"


def test_unicode_string_input_is_not_decoded_twice() -> None:
    """Provider callers can still pass an already decoded MIME string."""
    raw = (
        "Subject: Bekræft identitet\nContent-Type: text/html; charset=UTF-8\n\n"
        '<p><a href="https://unrelated.test">Bekræft med MitID</a></p>'
    )

    parsed = MimeParser.parse(raw)

    assert parsed.headers.subject == "Bekræft identitet"
    assert parsed.link_details[0].text == "Bekræft med MitID"


def test_duplicate_identity_and_authentication_headers_keep_first_value() -> None:
    """Header decoding must not silently change duplicate-header selection."""
    parsed = MimeParser.parse(
        "From: First <first@example.com>\nFrom: Second <second@example.net>\n"
        "Authentication-Results: trusted.example; dmarc=fail\n"
        "Authentication-Results: other.example; dmarc=pass\n\nHello"
    )

    assert parsed.headers.from_addr == "First <first@example.com>"
    assert parsed.headers.authentication_results == "trusted.example; dmarc=fail"


def test_unrelated_blocks_do_not_supply_sensitive_action_context() -> None:
    """A security article or footer must not taint an unrelated travel destination."""
    parsed = MimeParser.parse(
        _html_mail(
            "<div><p>Never confirm your identity from unexpected emails.</p>"
            '<p>Brazil holidays: <a href="https://hotel.com.br">View rooms</a></p>'
            "<footer>MitID security advice: protect your password.</footer></div>"
        )
    )

    assert parsed.link_details[0].context == "Brazil holidays: View rooms"


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_plain_urls_have_bounded_paragraph_context_and_keep_balanced_parentheses(
    newline: str,
) -> None:
    """Plain links retain nearby instructions, without including distant paragraphs."""
    parsed = MimeParser.parse(
        (
            "Subject: Travel\n\nNever confirm your identity by email.\n\n"
            "See our hotel: https://hotel.com.br/rooms_(family).\n\n"
            "Keep your MitID password private."
        ).replace("\n", newline)
    )

    assert parsed.links == ["https://hotel.com.br/rooms_(family)"]
    assert parsed.link_details[0].context == ("See our hotel: https://hotel.com.br/rooms_(family).")


def test_long_context_is_capped_near_link_and_identical_links_are_deduplicated() -> None:
    """Long text cannot bury a button's label outside its retained local context."""
    paragraph = (
        "<p>"
        + "Earlier text " * 150
        + '<a href="https://example.test">Confirm your identity</a>'
        + " Later text" * 150
        + "</p>"
    )
    parsed = MimeParser.parse(_html_mail(paragraph + paragraph))

    assert len(parsed.link_details) == 1
    assert "Confirm your identity" in parsed.link_details[0].context
    assert len(parsed.link_details[0].context) <= 500


def test_displayed_url_is_a_label_and_does_not_become_another_destination() -> None:
    """A trusted-looking displayed URL preserves its actual unrelated href."""
    parsed = MimeParser.parse(
        _html_mail('<p><a href="https://unrelated.test">https://skat.dk/login</a></p>')
    )

    assert parsed.links == ["https://unrelated.test"]
    assert parsed.link_details[0].text == "https://skat.dk/login"


def test_malformed_html_with_optional_end_tags_still_isolates_context() -> None:
    """Missing closing paragraph tags do not merge unrelated body sections."""
    parsed = MimeParser.parse(
        _html_mail(
            "<p>Verify your identity" '<p><a href="https://hotel.com.br"><strong>View rooms</a>'
        )
    )

    assert parsed.link_details[0].text == "View rooms"
    assert parsed.link_details[0].context == "View rooms"


def test_skat_sample_preserves_the_mitid_button_relationship() -> None:
    """The real regression sample retains its decoded label and actual destination."""
    path = Path(__file__).resolve().parents[2] / "samples" / "skat_mail.eml"
    parsed = MimeParser.parse(path.read_bytes())

    assert parsed.link_details[0].text == "Bekræft med MitID"
    assert parsed.link_details[0].url == "https://abcd.zanuto.adv.br/url/digital/"
    assert "box-sizing" not in parsed.body.get_content()
    assert "identitetsbekræftelse via MitID" in parsed.body.get_content()


def test_email_body_without_parser_keeps_legacy_fallback() -> None:
    """Existing provider-created body models retain their prior text fallback."""
    assert EmailBody(text="Plain", html="<p>HTML</p>").get_content() == "Plain"
    assert EmailBody(html="<p>Hidden</p>", visible_text="").get_content() == ""
