"""Phishing analysis for raw e-mail messages (.eml)."""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser

from phishguard.analyzer import Report, analyze_url, verdict_for
from phishguard.brands import BRANDS, skeleton
from phishguard.features import InvalidURLError, parse_url
from phishguard.rules import Finding

MAX_EMAIL_BYTES = 5 * 1024 * 1024
MAX_LINKS = 50

_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]+", re.IGNORECASE)
_DOMAIN_LIKE_RE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE)
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

BRAND_RULES = frozenset({"brand_unofficial_domain", "homoglyph", "combosquatting", "typosquatting",
                         "brand_in_domain", "mixed_scripts"})

AUTH_FAILURE_WEIGHTS = {
    ("dmarc", "fail"): 25,
    ("spf", "fail"): 20,
    ("spf", "softfail"): 10,
    ("dkim", "fail"): 15,
}

URGENCY_PHRASES = (
    # Spanish
    "urgente", "inmediatamente", "suspendida", "suspendido", "bloqueada", "bloqueado",
    "24 horas", "48 horas", "verifique su cuenta", "verifica tu cuenta", "confirme sus datos",
    "confirma tus datos", "actividad inusual", "acceso no autorizado", "será cancelada",
    "último aviso", "ultimo aviso",
    # English
    "urgent", "immediately", "suspended", "locked", "within 24 hours", "verify your account",
    "confirm your identity", "unusual activity", "unauthorized access", "final notice",
)

EXECUTABLE_ATTACHMENTS = (".exe", ".scr", ".js", ".vbs", ".hta", ".bat", ".cmd", ".ps1", ".msi",
                          ".jar", ".lnk", ".iso", ".img", ".html", ".htm", ".shtml", ".svg",
                          ".docm", ".xlsm", ".pptm")
ARCHIVE_ATTACHMENTS = (".zip", ".rar", ".7z", ".gz", ".tar")
DOCUMENT_DECOYS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt")


class InvalidEmailError(ValueError):
    """Raised when the input cannot be parsed as an e-mail message."""


@dataclass
class LinkResult:
    url: str
    text: str
    report: Report

    def to_dict(self) -> dict:
        return {"url": self.url, "text": self.text, "report": self.report.to_dict()}


@dataclass
class EmailReport:
    subject: str
    sender: str
    sender_domain: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    links: list[LinkResult] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "score": self.score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "links": [link.to_dict() for link in self.links],
            "attachments": self.attachments,
        }


class _LinkExtractor(HTMLParser):
    """Collects (href, visible text) pairs and the visible text of an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _registered_domain(host_or_url: str) -> str:
    try:
        return parse_url(host_or_url).registered_domain
    except InvalidURLError:
        return ""


def _domain_of(address: str) -> str:
    _, addr = parseaddr(address)
    return addr.rpartition("@")[2].lower().strip(">") if "@" in addr else ""


def _part_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, KeyError, ValueError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_email(data: bytes | str) -> EmailMessage:
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
    if not raw.strip():
        raise InvalidEmailError("el correo está vacío")
    if len(raw) > MAX_EMAIL_BYTES:
        raise InvalidEmailError(f"el correo supera {MAX_EMAIL_BYTES // (1024 * 1024)} MB")
    message = email.message_from_bytes(raw, policy=policy.default)
    if not message.keys():
        raise InvalidEmailError("no se encontraron cabeceras de correo")
    return message


def _check_authentication(message: EmailMessage) -> list[Finding]:
    headers = message.get_all("Authentication-Results", []) + message.get_all("Received-SPF", [])
    results: dict[str, str] = {}
    for header in headers:
        for mechanism, result in _AUTH_RE.findall(str(header)):
            results.setdefault(mechanism.lower(), result.lower())
    for header in message.get_all("Received-SPF", []):
        verdict = str(header).split(None, 1)[0].lower() if str(header).strip() else ""
        results.setdefault("spf", verdict)

    findings = []
    for mechanism in ("dmarc", "spf", "dkim"):
        result = results.get(mechanism)
        weight = AUTH_FAILURE_WEIGHTS.get((mechanism, result or ""))
        if weight:
            findings.append(Finding(f"{mechanism}_{result}", weight,
                                    f"La verificación {mechanism.upper()} falló: "
                                    "el remitente puede estar falsificado.",
                                    f"{mechanism}={result}"))
    if not results:
        findings.append(Finding("auth_unknown", 0,
                                "El correo no incluye resultados de SPF/DKIM/DMARC; "
                                "no se pudo verificar el remitente."))
    return findings


def _check_sender(message: EmailMessage, sender_domain: str) -> list[Finding]:
    findings: list[Finding] = []
    display_name, _ = parseaddr(str(message.get("From", "")))
    sender_registered = _registered_domain(sender_domain) if sender_domain else ""
    name_skeleton = skeleton(display_name)

    for brand, official in BRANDS.items():
        if len(brand) >= 4 and skeleton(brand) in name_skeleton and sender_registered not in official:
            findings.append(Finding("display_name_spoof", 30,
                                    f"El nombre del remitente dice '{brand}' "
                                    "pero el correo viene de otro dominio.",
                                    f"{display_name} <{sender_domain}>"))
            break

    if sender_domain:
        sender_report = analyze_url(sender_domain)
        for finding in sender_report.findings:
            if finding.rule in BRAND_RULES:
                findings.append(Finding(f"sender_{finding.rule}", finding.weight,
                                        f"Dominio del remitente: {finding.message}", sender_domain))
                break

    for header, rule_name, weight, message_text in (
        ("Reply-To", "reply_to_mismatch", 15, "Las respuestas (Reply-To) van a otro dominio."),
        ("Return-Path", "return_path_mismatch", 10, "El servidor de envío (Return-Path) es de otro dominio."),
    ):
        other = _domain_of(str(message.get(header, "")))
        if other and sender_registered and _registered_domain(other) != sender_registered:
            findings.append(Finding(rule_name, weight, message_text, f"{sender_domain} → {other}"))
    return findings


def _check_attachments(names: list[str]) -> list[Finding]:
    findings = []
    for name in names:
        lower = name.lower()
        if lower.endswith(EXECUTABLE_ATTACHMENTS):
            if any(f"{decoy}." in lower for decoy in DOCUMENT_DECOYS):
                findings.append(Finding("double_extension", 35,
                                        "Adjunto con doble extensión para ocultar un ejecutable.", name))
            else:
                findings.append(Finding("dangerous_attachment", 25,
                                        "Adjunto de un tipo que puede ejecutar código "
                                        "o abrir un formulario falso.", name))
        elif lower.endswith(ARCHIVE_ATTACHMENTS):
            findings.append(Finding("archive_attachment", 10,
                                    "Adjunto comprimido: suele usarse para evadir filtros antivirus.", name))
    return findings


def analyze_email(data: bytes | str) -> EmailReport:
    """Analyze a raw RFC 822 message. Raises InvalidEmailError for unparseable input."""
    message = parse_email(data)
    subject = str(message.get("Subject", "") or "")
    sender = str(message.get("From", "") or "")
    sender_domain = _domain_of(sender)

    link_pairs: list[tuple[str, str]] = []
    text_parts: list[str] = [subject]
    attachments: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(filename or "(sin nombre)")
            continue
        content_type = part.get_content_type()
        if content_type == "text/html":
            extractor = _LinkExtractor()
            extractor.feed(_part_text(part))
            link_pairs.extend(extractor.links)
            text_parts.append(" ".join(extractor.text_parts))
        elif content_type == "text/plain":
            body = _part_text(part)
            text_parts.append(body)
            link_pairs.extend((url, "") for url in _URL_RE.findall(body))

    findings = _check_authentication(message) + _check_sender(message, sender_domain)
    findings += _check_attachments(attachments)

    text = " ".join(text_parts).lower()
    urgent = sorted({phrase for phrase in URGENCY_PHRASES
                     if re.search(rf"\b{re.escape(phrase)}\b", text)})
    if urgent:
        findings.append(Finding("urgency_language", min(5 * len(urgent), 15),
                                "Usa lenguaje de urgencia o amenaza para presionar al destinatario.",
                                ", ".join(urgent)))

    links: list[LinkResult] = []
    seen: set[str] = set()
    deceptive: list[str] = []
    for url, anchor in link_pairs:
        if not url.lower().startswith(("http://", "https://", "javascript:", "data:")) or url in seen:
            continue
        seen.add(url)
        if len(links) >= MAX_LINKS:
            break
        try:
            report = analyze_url(url)
        except InvalidURLError:
            continue
        links.append(LinkResult(url=url, text=anchor, report=report))
        if anchor and _DOMAIN_LIKE_RE.match(anchor):
            shown = _registered_domain(anchor)
            if shown and shown != report.registered_domain:
                deceptive.append(f"muestra {shown}, lleva a {report.registered_domain}")

    if deceptive:
        findings.append(Finding("deceptive_link", 30,
                                "El texto de un enlace muestra un dominio pero apunta a otro.",
                                "; ".join(deceptive[:3])))

    if links:
        worst = max(links, key=lambda link: link.report.score)
        if worst.report.verdict == "phishing":
            findings.append(Finding("phishing_link", 35, "Contiene un enlace clasificado como phishing.",
                                    worst.url))
        elif worst.report.verdict == "suspicious":
            findings.append(Finding("suspicious_link", 15, "Contiene un enlace sospechoso.", worst.url))

    findings.sort(key=lambda f: f.weight, reverse=True)
    score = min(100, sum(f.weight for f in findings))
    return EmailReport(
        subject=subject,
        sender=sender,
        sender_domain=sender_domain,
        score=score,
        verdict=verdict_for(score),
        findings=findings,
        links=sorted(links, key=lambda link: link.report.score, reverse=True),
        attachments=attachments,
    )
