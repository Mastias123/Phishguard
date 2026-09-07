"""Domain comparisons must respect registry boundaries and shared service tenants."""

import pytest
import requests

from phishguard.analyzers.domains import (
    address_domain,
    country_suffix,
    domain_matches,
    normalize_host,
    registrable_domain,
    same_domain,
    url_host,
)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("abcd.zanuto.adv.br", "zanuto.adv.br"),
        ("different.adv.br", "different.adv.br"),
        ("www.example.co.uk", "example.co.uk"),
        ("first.github.io", "first.github.io"),
        ("WWW.Example.COM.", "example.com"),
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("one.unlisted-suffix", "one.unlisted-suffix"),
        ("", ""),
    ],
)
def test_registered_domains(host: str, expected: str) -> None:
    """Resolve public/private suffix boundaries while preserving unknown hosts."""
    assert registrable_domain(host) == expected


def test_unrelated_registrants_and_shared_platform_tenants() -> None:
    """Unrelated registrants cannot inherit trust through a shared suffix."""
    assert not same_domain("abcd.zanuto.adv.br", "different.adv.br")
    assert not same_domain("first.github.io", "second.github.io")
    assert not same_domain("one.unlisted-suffix", "two.unlisted-suffix")
    assert not same_domain("", "")
    assert same_domain("jobs.indeed.com", "dk.indeed.com")


def test_domain_matching_uses_whole_labels_and_idna() -> None:
    """Lookalike suffixes and substrings must not pass a configured domain check."""
    assert domain_matches("LOGIN.SKAT.DK.", ("skat.dk",))
    assert not domain_matches("skat.dk.attacker.com", ("skat.dk",))
    assert not domain_matches("fakeskat.dk", ("skat.dk",))
    assert normalize_host("bücher.de") == "xn--bcher-kva.de"
    assert same_domain("bücher.de", "xn--bcher-kva.de")
    assert not same_domain("faß.de", "fass.de")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://user@evil.com/skat.dk", "evil.com"),
        ("//example.com/login", "example.com"),
        ("https://[2001:db8::1]/", "2001:db8::1"),
        ("https://[broken/", ""),
        ("https://example.com:wrong/", ""),
        ("https://example.com:99999/", ""),
        ("https://not a host.com/", ""),
        ("javascript:alert(1)", ""),
    ],
)
def test_url_host_validation(value: str, expected: str) -> None:
    """Malformed URLs stay untrusted without aborting analysis."""
    assert url_host(value) == expected


def test_country_is_optional_context() -> None:
    """Generic, unknown and IP destinations do not imply a country."""
    assert country_suffix("abcd.zanuto.adv.br") == "br"
    assert country_suffix("skat.dk") == "dk"
    assert country_suffix("example.com") is None
    assert country_suffix("example.unknown") is None
    assert country_suffix("192.0.2.1") is None
    assert address_domain('"Support @ Example" <help@EXAMPLE.COM>') == "example.com"


def test_suffix_extraction_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh PSL extractor can analyze a message without fetching any URLs."""
    import importlib

    from phishguard.analyzers import domains

    def reject_request(*args: object, **kwargs: object) -> None:
        raise AssertionError("Email analysis must not request network resources")

    monkeypatch.setattr(requests.sessions.Session, "request", reject_request)
    importlib.reload(domains)
    assert domains.registrable_domain("abcd.zanuto.adv.br") == "zanuto.adv.br"

