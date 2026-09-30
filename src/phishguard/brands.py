"""Commonly impersonated brands and lookalike-character normalization."""

from __future__ import annotations

# Brand keyword -> registrable domains legitimately owned by that brand.
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "google": frozenset({"google.com", "google.com.mx", "google.es", "gmail.com", "youtube.com"}),
    "gmail": frozenset({"gmail.com", "google.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "icloud": frozenset({"icloud.com", "apple.com"}),
    "microsoft": frozenset({
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
        "office.com", "office365.com", "xbox.com",
    }),
    "outlook": frozenset({"outlook.com", "live.com", "office.com", "microsoft.com"}),
    "office365": frozenset({"office.com", "office365.com", "microsoft.com"}),
    "amazon": frozenset({
        "amazon.com", "amazon.com.mx", "amazon.es", "amazon.co.uk", "amazon.de",
        "amazon.fr", "amazon.it", "amazon.ca", "amazon.com.br", "amazon.co.jp",
    }),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "fb.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "whatsapp": frozenset({"whatsapp.com", "whatsapp.net"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "adobe": frozenset({"adobe.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com"}),
    "metamask": frozenset({"metamask.io"}),
    "steamcommunity": frozenset({"steamcommunity.com", "steampowered.com"}),
    "fedex": frozenset({"fedex.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bankofamerica": frozenset({"bankofamerica.com"}),
    "bbva": frozenset({"bbva.com", "bbva.mx", "bbva.es"}),
    "santander": frozenset({"santander.com", "santander.com.mx", "bancosantander.es"}),
    "banamex": frozenset({"banamex.com"}),
    "banorte": frozenset({"banorte.com"}),
    "mercadolibre": frozenset({"mercadolibre.com", "mercadolibre.com.mx", "mercadolibre.com.ar"}),
    "mercadopago": frozenset({"mercadopago.com", "mercadopago.com.mx", "mercadopago.com.ar"}),
}

OFFICIAL_DOMAINS: frozenset[str] = frozenset().union(*BRANDS.values())

# Characters that render (nearly) identically to Latin letters.
_CONFUSABLE_CHARS = {
    # digits and symbols
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
    # i, l, | and 1 are interchangeable at a glance
    "i": "l", "|": "l",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "l", "ј": "j", "ԁ": "d", "һ": "h", "ѕ": "s", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "l", "κ": "k",
}
_CONFUSABLE_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def skeleton(text: str) -> str:
    """Collapse visually confusable characters so lookalike strings compare equal."""
    result = "".join(_CONFUSABLE_CHARS.get(ch, ch) for ch in text.lower())
    for seq, replacement in _CONFUSABLE_SEQUENCES:
        result = result.replace(seq, replacement)
    return result


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]
