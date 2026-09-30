from pathlib import Path

import pytest

from phishguard.email_analyzer import MAX_EMAIL_BYTES, InvalidEmailError, analyze_email

EMAILS = Path(__file__).resolve().parent.parent / "data" / "emails"


def rules(report) -> set[str]:
    return {f.rule for f in report.findings}


def make_email(headers: str, body: str = "Hola", content_type: str = "text/plain") -> str:
    return f"{headers}\nMIME-Version: 1.0\nContent-Type: {content_type}; charset=utf-8\n\n{body}\n"


def test_phishing_sample_is_flagged():
    report = analyze_email((EMAILS / "phishing_bbva.eml").read_bytes())
    assert report.verdict == "phishing"
    assert {"dmarc_fail", "spf_fail", "display_name_spoof", "reply_to_mismatch", "deceptive_link",
            "double_extension", "urgency_language", "phishing_link"} <= rules(report)
    assert report.attachments == ["estado_de_cuenta.pdf.exe"]
    assert report.sender_domain == "bbva-mx-seguridad.com"


def test_legitimate_sample_is_low_risk():
    report = analyze_email((EMAILS / "legit_github.eml").read_bytes())
    assert report.verdict == "low_risk"
    assert report.score == 0
    assert len(report.links) == 2  # duplicate URL is analyzed once


def test_missing_authentication_is_informational():
    report = analyze_email(make_email("From: Ana <ana@example.com>\nSubject: Hola"))
    auth = [f for f in report.findings if f.rule == "auth_unknown"]
    assert auth and auth[0].weight == 0


def test_sender_lookalike_domain():
    report = analyze_email(make_email("From: Soporte <help@paypa1.com>\nSubject: Aviso"))
    assert "sender_homoglyph" in rules(report)


def test_display_name_spoof_not_triggered_for_official_domain():
    report = analyze_email(make_email("From: PayPal <service@paypal.com>\nSubject: Recibo"))
    assert "display_name_spoof" not in rules(report)


def test_deceptive_link_detected_in_html():
    html = '<a href="https://evil.example/login">https://www.paypal.com</a>'
    report = analyze_email(make_email("From: a@example.com\nSubject: x", html, "text/html"))
    assert "deceptive_link" in rules(report)


def test_matching_link_text_is_not_deceptive():
    html = '<a href="https://www.example.com/a">example.com</a>'
    report = analyze_email(make_email("From: a@example.com\nSubject: x", html, "text/html"))
    assert "deceptive_link" not in rules(report)


def test_huge_anchor_text_is_handled_quickly():
    import time

    anchor = "a." * 50_000 + "!"
    html = f'<a href="https://example.com/">{anchor}</a>'
    started = time.perf_counter()
    analyze_email(make_email("From: a@example.com\nSubject: x", html, "text/html"))
    assert time.perf_counter() - started < 2


def test_urgency_matches_whole_words():
    report = analyze_email(make_email("From: a@example.com\nSubject: Es urgente", "Hola"))
    urgency = next(f for f in report.findings if f.rule == "urgency_language")
    assert urgency.evidence == "urgente"


def test_script_content_is_ignored_for_text():
    html = "<script>var urgente = 1;</script><p>Hola</p>"
    report = analyze_email(make_email("From: a@example.com\nSubject: x", html, "text/html"))
    assert "urgency_language" not in rules(report)


@pytest.mark.parametrize("bad", ["", "   ", b"\x00" * 10])
def test_invalid_email(bad):
    with pytest.raises(InvalidEmailError):
        analyze_email(bad)


def test_oversized_email():
    with pytest.raises(InvalidEmailError):
        analyze_email("x" * (MAX_EMAIL_BYTES + 1))
