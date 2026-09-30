"""Turns rule findings into a risk score and verdict."""

from __future__ import annotations

from dataclasses import dataclass, field

from phishguard.brands import OFFICIAL_DOMAINS
from phishguard.features import ParsedURL, parse_url
from phishguard.ml import load_model
from phishguard.rules import Finding, run_rules

PHISHING_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30

# The domain model has ~2% false positives at p>=0.8 (see model metadata), so it only adds
# weight at high confidence and can never reach SUSPICIOUS_THRESHOLD on its own.
ML_WEIGHTS = ((0.9, 20), (0.8, 10))


@dataclass
class Report:
    url: str
    normalized_url: str
    host: str
    registered_domain: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    ml_probability: float | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "registered_domain": self.registered_domain,
            "score": self.score,
            "verdict": self.verdict,
            "ml_probability": self.ml_probability,
            "findings": [f.to_dict() for f in self.findings],
        }


def verdict_for(score: int) -> str:
    if score >= PHISHING_THRESHOLD:
        return "phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "low_risk"


def analyze_url(url: str) -> Report:
    """Analyze a URL offline. Raises InvalidURLError for unparseable input."""
    parsed = parse_url(url)
    findings = run_rules(parsed)
    probability = ml_probability(parsed)
    if probability is not None:
        for threshold, weight in ML_WEIGHTS:
            if probability >= threshold:
                findings.append(Finding("ml_model", weight,
                                        "El modelo de ML considera que el nombre del dominio se parece "
                                        "a dominios de phishing conocidos.",
                                        f"probabilidad {probability:.1%}"))
                findings.sort(key=lambda f: f.weight, reverse=True)
                break
    score = min(100, sum(f.weight for f in findings))
    return Report(
        url=url,
        normalized_url=parsed.normalized,
        host=parsed.host_unicode,
        registered_domain=parsed.registered_domain,
        score=score,
        verdict=verdict_for(score),
        findings=findings,
        ml_probability=probability,
    )


def ml_probability(parsed: ParsedURL) -> float | None:
    model = load_model()
    if model is None or parsed.is_ip or not parsed.domain or not parsed.suffix:
        return None
    if parsed.registered_domain in OFFICIAL_DOMAINS:
        return None
    return round(model.predict_proba(parsed.domain_unicode, parsed.suffix), 4)
