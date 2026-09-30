"""Explainable heuristic rules. Each rule inspects a ParsedURL and yields Findings."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass

from phishguard.brands import BRANDS, OFFICIAL_DOMAINS, levenshtein, skeleton
from phishguard.features import ParsedURL, shannon_entropy


@dataclass(frozen=True)
class Finding:
    rule: str
    weight: int
    message: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


Rule = Callable[[ParsedURL], Iterable[Finding]]
RULES: list[Rule] = []


def rule(func: Rule) -> Rule:
    RULES.append(func)
    return func


SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "country", "kim", "rest", "fit", "support", "cam", "icu", "buzz",
    "monster", "quest", "sbs", "cfd", "bond", "lol", "beauty", "hair",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id",
})

# Platforms where anyone can host content under a trusted-looking domain.
FREE_HOSTING = frozenset({
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "github.io", "netlify.app", "vercel.app", "pages.dev", "herokuapp.com",
    "glitch.me", "repl.co", "blogspot.com", "sites.google.com", "forms.gle",
    "ngrok.io", "ngrok-free.app", "workers.dev", "r2.dev", "ipfs.io",
})

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "logon", "verify", "verification", "update", "secure",
    "account", "banking", "confirm", "password", "wallet", "suspend", "unlock",
    "billing", "invoice", "recover", "webscr", "authenticate",
    # Spanish
    "verificar", "cuenta", "actualizar", "seguridad", "banca", "acceso",
    "contrasena", "desbloquear", "factura", "confirmar",
)

RISKY_EXTENSIONS = (".exe", ".scr", ".apk", ".msi", ".bat", ".js", ".vbs", ".hta", ".iso", ".lnk")


@rule
def dangerous_scheme(p: ParsedURL) -> Iterator[Finding]:
    if p.scheme in ("javascript", "data", "vbscript"):
        yield Finding("dangerous_scheme", 60,
                      f"El esquema '{p.scheme}:' puede ejecutar código o incrustar contenido.",
                      p.scheme)


@rule
def ip_host(p: ParsedURL) -> Iterator[Finding]:
    if p.is_ip:
        yield Finding("ip_host", 25,
                      "El host es una dirección IP en lugar de un nombre de dominio.", p.host)


@rule
def userinfo_in_url(p: ParsedURL) -> Iterator[Finding]:
    if p.userinfo:
        yield Finding("userinfo", 25,
                      "La URL contiene '@': todo lo anterior se ignora y el destino real es otro host.",
                      p.userinfo)


@rule
def url_length(p: ParsedURL) -> Iterator[Finding]:
    length = len(p.normalized)
    if length > 150:
        yield Finding("long_url", 10, "La URL es muy larga (posible ofuscación).", str(length))
    elif length > 75:
        yield Finding("long_url", 5, "La URL es larga.", str(length))


@rule
def many_subdomains(p: ParsedURL) -> Iterator[Finding]:
    labels = p.subdomain_labels
    if labels and labels[0] == "www":
        labels = labels[1:]
    if len(labels) >= 3:
        yield Finding("many_subdomains", 10,
                      "Demasiados subdominios; suelen usarse para esconder el dominio real.",
                      p.subdomain)


@rule
def suspicious_tld(p: ParsedURL) -> Iterator[Finding]:
    tld = p.suffix.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        yield Finding("suspicious_tld", 10,
                      "El dominio de nivel superior se abusa con frecuencia en phishing.", f".{tld}")


@rule
def punycode(p: ParsedURL) -> Iterator[Finding]:
    if "xn--" not in p.host:
        return
    scripts = set()
    for ch in p.host_unicode:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "UNKNOWN").split(" ")[0])
    if len(scripts) > 1:
        yield Finding("mixed_scripts", 30,
                      "El dominio mezcla alfabetos (p. ej. latino y cirílico): posible ataque homógrafo.",
                      f"{p.host_unicode} ({', '.join(sorted(scripts))})")
    else:
        yield Finding("punycode", 15, "El dominio usa caracteres internacionales (punycode).",
                      p.host_unicode)


@rule
def brand_impersonation(p: ParsedURL) -> Iterator[Finding]:
    """Report the strongest sign of a brand name being abused outside its official domains."""
    if p.is_ip or not p.domain or p.registered_domain in OFFICIAL_DOMAINS:
        return

    label = p.domain_unicode.lower()
    label_skeleton = skeleton(label)
    token_skeletons = {skeleton(token) for token in re.split(r"[-_]", label)}
    subdomain = p.subdomain.lower()
    path = f"{p.path}?{p.query}".lower()
    candidates: list[Finding] = []

    for brand in BRANDS:
        brand_skeleton = skeleton(brand)
        if label == brand:
            candidates.append(Finding("brand_unofficial_domain", 30,
                                      f"Usa el nombre '{brand}' pero no es un dominio oficial de la marca.",
                                      p.registered_domain))
        elif label_skeleton == brand_skeleton:
            candidates.append(Finding("homoglyph", 40,
                                      f"El dominio imita visualmente a '{brand}' con caracteres parecidos.",
                                      p.domain_unicode))
        elif brand_skeleton in token_skeletons:
            candidates.append(Finding("combosquatting", 30,
                                      f"El dominio combina la marca '{brand}' con otras palabras.",
                                      p.registered_domain))
        elif _is_typo(label_skeleton, brand_skeleton):
            candidates.append(Finding("typosquatting", 35,
                                      f"El dominio es casi idéntico a '{brand}' (error tipográfico).",
                                      p.domain_unicode))
        elif brand_skeleton in label_skeleton and len(brand) >= 5:
            candidates.append(Finding("brand_in_domain", 15,
                                      f"El dominio contiene la marca '{brand}'.", p.registered_domain))
        elif brand in subdomain:
            candidates.append(Finding("brand_in_subdomain", 25,
                                      f"La marca '{brand}' aparece en el subdominio, no en el dominio real.",
                                      p.host))
        elif len(brand) >= 5 and brand in path:
            candidates.append(Finding("brand_in_path", 10,
                                      f"La marca '{brand}' aparece en la ruta de un dominio ajeno.",
                                      brand))

    if candidates:
        yield max(candidates, key=lambda f: f.weight)


def _is_typo(label: str, brand: str) -> bool:
    if len(brand) < 6 or abs(len(label) - len(brand)) > 2:
        return False
    max_distance = 2 if len(brand) >= 9 else 1
    return 0 < levenshtein(label, brand) <= max_distance


@rule
def no_https(p: ParsedURL) -> Iterator[Finding]:
    if p.scheme == "http":
        yield Finding("no_https", 5, "La conexión no está cifrada (HTTP).")


@rule
def url_shortener(p: ParsedURL) -> Iterator[Finding]:
    if p.registered_domain in URL_SHORTENERS or p.host in URL_SHORTENERS:
        yield Finding("url_shortener", 10, "Acortador de URLs: el destino real está oculto.", p.host)


@rule
def free_hosting(p: ParsedURL) -> Iterator[Finding]:
    for platform in FREE_HOSTING:
        if p.host == platform or p.host.endswith(f".{platform}"):
            yield Finding("free_hosting", 10,
                          "Alojado en una plataforma gratuita donde cualquiera puede publicar.",
                          platform)
            return


@rule
def suspicious_keywords(p: ParsedURL) -> Iterator[Finding]:
    haystack = f"{p.host} {p.path} {p.query}".lower()
    found = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack})
    if found:
        yield Finding("suspicious_keywords", min(5 * len(found), 15),
                      "Contiene palabras típicas de páginas de robo de credenciales.",
                      ", ".join(found))


@rule
def hyphenated_domain(p: ParsedURL) -> Iterator[Finding]:
    # Count on the Unicode form so the "xn--" punycode prefix is not mistaken for hyphens.
    if p.domain_unicode.count("-") >= 2:
        yield Finding("hyphenated_domain", 5, "El dominio tiene muchos guiones.", p.domain_unicode)


@rule
def non_standard_port(p: ParsedURL) -> Iterator[Finding]:
    if p.port is not None and p.port not in (80, 443):
        yield Finding("non_standard_port", 10, "Usa un puerto no estándar.", str(p.port))


@rule
def random_looking_domain(p: ParsedURL) -> Iterator[Finding]:
    if p.is_ip or len(p.domain) < 12:
        return
    entropy = shannon_entropy(p.domain)
    digits = sum(ch.isdigit() for ch in p.domain)
    if entropy > 3.5 or digits >= 4:
        yield Finding("random_domain", 10,
                      "El dominio parece generado aleatoriamente.",
                      f"{p.domain} (entropía {entropy:.2f})")


@rule
def embedded_redirect(p: ParsedURL) -> Iterator[Finding]:
    target = f"{p.path}?{p.query}".lower()
    if "//" in p.path or re.search(r"=(https?%3a|https?:)", target):
        yield Finding("embedded_redirect", 10,
                      "La URL contiene otra URL (posible redirección abierta).")


@rule
def risky_download(p: ParsedURL) -> Iterator[Finding]:
    path = p.path.lower()
    for ext in RISKY_EXTENSIONS:
        if path.endswith(ext):
            yield Finding("risky_download", 25, "Enlaza directamente a un archivo ejecutable.", ext)
            return


def run_rules(parsed: ParsedURL) -> list[Finding]:
    findings: list[Finding] = []
    for check in RULES:
        findings.extend(check(parsed))
    return sorted(findings, key=lambda f: f.weight, reverse=True)
