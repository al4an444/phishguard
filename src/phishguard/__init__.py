"""PhishGuard: explainable phishing detection for URLs."""

from phishguard.analyzer import Report, analyze_url
from phishguard.features import InvalidURLError, ParsedURL, parse_url
from phishguard.rules import Finding

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "InvalidURLError",
    "ParsedURL",
    "Report",
    "__version__",
    "analyze_url",
    "parse_url",
]
