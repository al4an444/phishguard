import pytest

from phishguard.features import InvalidURLError, parse_url, shannon_entropy


def test_adds_scheme_when_missing():
    parsed = parse_url("example.com/login")
    assert parsed.scheme == "http"
    assert parsed.host == "example.com"
    assert parsed.path == "/login"


def test_splits_registered_domain_with_multi_part_suffix():
    parsed = parse_url("https://secure.login.amazon.co.uk/x")
    assert parsed.domain == "amazon"
    assert parsed.suffix == "co.uk"
    assert parsed.registered_domain == "amazon.co.uk"
    assert parsed.subdomain_labels == ["secure", "login"]


def test_detects_userinfo():
    parsed = parse_url("http://paypal.com@evil.example/")
    assert parsed.userinfo == "paypal.com"
    assert parsed.host == "evil.example"


@pytest.mark.parametrize("host", ["192.168.0.1", "[::1]", "3232235777", "0xC0A80001"])
def test_detects_ip_hosts(host):
    assert parse_url(f"http://{host}/").is_ip


def test_decodes_punycode():
    parsed = parse_url("https://xn--pypal-4ve.com/")
    assert parsed.host == "xn--pypal-4ve.com"
    assert parsed.host_unicode == "pаypal.com"  # Cyrillic 'а'


def test_encodes_unicode_host_to_punycode():
    parsed = parse_url("https://pаypal.com/")
    assert parsed.host.startswith("xn--")


def test_dangerous_scheme_is_parsed_without_host():
    parsed = parse_url("javascript:alert(1)")
    assert parsed.scheme == "javascript"
    assert parsed.host == ""


@pytest.mark.parametrize("bad", ["", "   ", "http://", "http://example.com:99999", "x" * 5000])
def test_rejects_invalid_input(bad):
    with pytest.raises(InvalidURLError):
        parse_url(bad)


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
