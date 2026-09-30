import pytest

from phishguard import analyze_url
from phishguard.analyzer import verdict_for


@pytest.mark.parametrize("url", [
    "https://www.google.com/",
    "https://github.com/python/cpython",
    "https://www.paypal.com/signin",
    "https://es.wikipedia.org/wiki/Phishing",
    "https://www.mercadolibre.com.mx/",
])
def test_legitimate_urls_are_low_risk(url):
    assert analyze_url(url).verdict == "low_risk"


@pytest.mark.parametrize("url", [
    "http://paypa1-login.xyz/verify/account",
    "http://www.paypal.com@192.168.4.20/webscr?cmd=login",
    "https://xn--pypal-4ve.com/signin/confirm",
    "http://secure-bbva-mx.top/acceso/actualizar-cuenta",
])
def test_obvious_phishing_is_flagged(url):
    assert analyze_url(url).verdict == "phishing"


def test_score_is_capped_at_100():
    report = analyze_url("javascript:alert(1)//paypal-login-verify-account-secure.exe" * 3)
    assert 0 <= report.score <= 100


def test_report_serializes():
    data = analyze_url("https://paypa1.com/").to_dict()
    assert data["registered_domain"] == "paypa1.com"
    assert data["findings"][0]["rule"] == "homoglyph"
    assert set(data["findings"][0]) == {"rule", "weight", "message", "evidence"}


@pytest.mark.parametrize("score, verdict", [(0, "low_risk"), (29, "low_risk"), (30, "suspicious"),
                                            (59, "suspicious"), (60, "phishing"), (100, "phishing")])
def test_verdict_thresholds(score, verdict):
    assert verdict_for(score) == verdict
