"""URL parsing and normalization into the parts the rules inspect."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# Offline extractor: uses the Public Suffix List snapshot bundled with tldextract,
# so analysis never performs network requests.
_extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

MAX_URL_LENGTH = 4096
DANGEROUS_SCHEMES = ("javascript", "data", "vbscript")

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
# Obfuscated IPv4 forms browsers accept: 3232235777, 0xC0A80001, 0300.0250.0.1
_OBFUSCATED_IP_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$")


class InvalidURLError(ValueError):
    """Raised when the input cannot be interpreted as a URL."""


@dataclass(frozen=True)
class ParsedURL:
    raw: str
    normalized: str
    scheme: str
    host: str  # lowercase ASCII (punycode) form
    host_unicode: str  # human-readable form, IDN labels decoded
    port: int | None
    userinfo: str
    path: str
    query: str
    subdomain: str
    domain: str  # registrable label, e.g. "paypal" in "www.paypal.com"
    domain_unicode: str
    suffix: str
    is_ip: bool

    @property
    def registered_domain(self) -> str:
        if self.is_ip or not self.suffix:
            return self.domain
        return f"{self.domain}.{self.suffix}"

    @property
    def subdomain_labels(self) -> list[str]:
        return [label for label in self.subdomain.split(".") if label]


def _to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _to_unicode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_OBFUSCATED_IP_RE.match(host))


def parse_url(raw: str) -> ParsedURL:
    """Parse ``raw`` into a :class:`ParsedURL`. Adds ``http://`` if no scheme is given."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string")
    text = raw.strip()
    if not text:
        raise InvalidURLError("URL is empty")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL exceeds {MAX_URL_LENGTH} characters")

    scheme_match = _SCHEME_RE.match(text)
    if scheme_match and scheme_match.group(1).lower() in DANGEROUS_SCHEMES:
        scheme = scheme_match.group(1).lower()
        return ParsedURL(
            raw=raw, normalized=text, scheme=scheme, host="", host_unicode="",
            port=None, userinfo="", path=text[scheme_match.end():], query="",
            subdomain="", domain="", domain_unicode="", suffix="", is_ip=False,
        )

    normalized = text if "://" in text else f"http://{text}"
    parts = urlsplit(normalized)
    if not parts.hostname:
        raise InvalidURLError("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(f"invalid port: {exc}") from exc

    host = _to_ascii(parts.hostname.rstrip("."))
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    is_ip = _is_ip(host)

    if is_ip:
        subdomain, domain, suffix = "", host, ""
    else:
        ext = _extractor(host)
        subdomain, domain, suffix = ext.subdomain, ext.domain, ext.suffix

    return ParsedURL(
        raw=raw,
        normalized=normalized,
        scheme=parts.scheme.lower(),
        host=host,
        host_unicode=_to_unicode(host),
        port=port,
        userinfo=userinfo,
        path=parts.path,
        query=parts.query,
        subdomain=subdomain,
        domain=domain,
        domain_unicode=_to_unicode(domain),
        suffix=suffix,
        is_ip=is_ip,
    )


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())
