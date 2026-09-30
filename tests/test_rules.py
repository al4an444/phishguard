import pytest

from phishguard.brands import levenshtein, skeleton
from phishguard.features import parse_url
from phishguard.rules import run_rules


def rules_for(url: str) -> set[str]:
    return {f.rule for f in run_rules(parse_url(url))}


@pytest.mark.parametrize("url, expected", [
    ("javascript:alert(1)", "dangerous_scheme"),
    ("http://192.168.1.10/login", "ip_host"),
    ("http://www.paypal.com@evil.example/", "userinfo"),
    ("http://a.b.c.d.example.com/", "many_subdomains"),
    ("https://example.xyz/", "suspicious_tld"),
    ("https://xn--pypal-4ve.com/", "mixed_scripts"),
    ("https://paypal.xyz/", "brand_unofficial_domain"),
    ("https://paypa1.com/", "homoglyph"),
    ("https://rnicrosoft.com/", "homoglyph"),
    ("https://paypal-secure-login.com/", "combosquatting"),
    ("https://netfliix.com/", "typosquatting"),
    ("https://securepaypalhelp.com/", "brand_in_domain"),
    ("https://paypal.com.account-check.example/", "brand_in_subdomain"),
    ("https://example.com/paypal/signin", "brand_in_path"),
    ("http://example.com/", "no_https"),
    ("https://bit.ly/abc", "url_shortener"),
    ("https://my-bank.web.app/", "free_hosting"),
    ("https://example.com/verify-account", "suspicious_keywords"),
    ("https://example.com:8443/", "non_standard_port"),
    ("https://x7kq9zr2mv4wp8.com/", "random_domain"),
    ("https://example.com/redirect?to=https://evil.example", "embedded_redirect"),
    ("https://example.com/files/invoice.exe", "risky_download"),
])
def test_rule_triggers(url, expected):
    assert expected in rules_for(url)


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://accounts.google.com/",
    "https://login.microsoftonline.com/",
    "https://www.amazon.com.mx/",
])
def test_official_domains_do_not_trigger_brand_rules(url):
    brand_rules = {"brand_unofficial_domain", "homoglyph", "combosquatting", "typosquatting",
                   "brand_in_domain", "brand_in_subdomain", "brand_in_path"}
    assert not rules_for(url) & brand_rules


def test_only_strongest_brand_finding_is_reported():
    findings = [f for f in run_rules(parse_url("https://paypa1.com/paypal")) if "brand" in f.rule
                or f.rule in ("homoglyph", "typosquatting", "combosquatting")]
    assert len(findings) == 1
    assert findings[0].rule == "homoglyph"


def test_punycode_prefix_is_not_counted_as_hyphens():
    assert "hyphenated_domain" not in rules_for("https://xn--pypal-4ve.com/")
    assert "hyphenated_domain" in rules_for("https://secure-login-help.com/")


def test_short_brand_word_is_not_typosquatting():
    # "apply" is one edit away from "apple" but brands under 6 chars are skipped.
    assert "typosquatting" not in rules_for("https://apply.com/")


def test_findings_are_sorted_by_weight():
    weights = [f.weight for f in run_rules(parse_url("http://paypa1-login.xyz/verify?u=http://x"))]
    assert weights == sorted(weights, reverse=True)


def test_skeleton_and_levenshtein():
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
