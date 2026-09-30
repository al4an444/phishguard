"""Command-line interface: ``phishguard <url> [<url> ...]``."""

from __future__ import annotations

import argparse
import json
import sys

from phishguard import __version__
from phishguard.analyzer import Report, analyze_url
from phishguard.email_analyzer import EmailReport, InvalidEmailError, analyze_email
from phishguard.features import InvalidURLError

_VERDICT_LABELS = {
    "phishing": "PHISHING",
    "suspicious": "SOSPECHOSO",
    "low_risk": "RIESGO BAJO",
}
_VERDICT_RANK = {"low_risk": 0, "suspicious": 1, "phishing": 2}


def _format_text(report: Report) -> str:
    lines = [
        f"{report.url}",
        f"  Veredicto: {_VERDICT_LABELS[report.verdict]}  (score {report.score}/100)",
        f"  Dominio:   {report.registered_domain}",
    ]
    for finding in report.findings:
        evidence = f"  [{finding.evidence}]" if finding.evidence else ""
        lines.append(f"   +{finding.weight:<3} {finding.rule}: {finding.message}{evidence}")
    return "\n".join(lines)


def _format_email(report: EmailReport) -> str:
    lines = [
        f"Correo: {report.subject or '(sin asunto)'}",
        f"  De:        {report.sender}",
        f"  Veredicto: {_VERDICT_LABELS[report.verdict]}  (score {report.score}/100)",
    ]
    for finding in report.findings:
        evidence = f"  [{finding.evidence}]" if finding.evidence else ""
        lines.append(f"   +{finding.weight:<3} {finding.rule}: {finding.message}{evidence}")
    if report.links:
        lines.append(f"  Enlaces ({len(report.links)}):")
        for link in report.links:
            lines.append(f"    {link.report.score:>3}  {_VERDICT_LABELS[link.report.verdict]:<11} {link.url}")
    if report.attachments:
        lines.append(f"  Adjuntos: {', '.join(report.attachments)}")
    return "\n".join(lines)


def _run_email(path: str, as_json: bool) -> tuple[int, bool]:
    """Analyze one .eml file. Returns (verdict rank, had_error)."""
    try:
        with open(path, "rb") as fh:
            report = analyze_email(fh.read())
    except (OSError, InvalidEmailError) as exc:
        print(f"{path}\n  Error: {exc}", file=sys.stderr)
        return 0, True
    if as_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(_format_email(report))
    return _VERDICT_RANK[report.verdict], False


def _read_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
    return urls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard",
                                     description="Detector de phishing explicable para URLs.")
    parser.add_argument("urls", nargs="*", help="URLs a analizar")
    parser.add_argument("-f", "--file", help="archivo con una URL por línea")
    parser.add_argument("-e", "--email", metavar="ARCHIVO.eml", help="analizar un correo en formato .eml")
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    parser.add_argument("--fail-on", choices=["suspicious", "phishing"],
                        help="código de salida 1 si algún resultado alcanza este veredicto")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    urls = _read_urls(args)
    if not urls and not args.email:
        parser.error("indica al menos una URL, un archivo con --file o un correo con --email")

    # Unicode hostnames must not crash legacy Windows consoles.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    if args.email:
        if urls:
            parser.error("--email no se puede combinar con URLs")
        rank, failed = _run_email(args.email, args.json)
        if args.fail_on and rank >= _VERDICT_RANK[args.fail_on]:
            return 1
        return 2 if failed else 0

    results: list[dict] = []
    worst = 0
    errors = False
    for url in urls:
        try:
            report = analyze_url(url)
        except InvalidURLError as exc:
            errors = True
            results.append({"url": url, "error": str(exc)})
            if not args.json:
                print(f"{url}\n  Error: {exc}", file=sys.stderr)
            continue
        worst = max(worst, _VERDICT_RANK[report.verdict])
        results.append(report.to_dict())
        if not args.json:
            print(_format_text(report))

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=2))

    if args.fail_on and worst >= _VERDICT_RANK[args.fail_on]:
        return 1
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
