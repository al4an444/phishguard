"""Measure detection quality against a labeled CSV.

The CSV needs the columns ``url`` and ``label`` (1 = phishing, 0 = legitimate).
Public sources of labeled URLs: PhishTank, OpenPhish, the Tranco top list for legitimate domains.

    python scripts/evaluate.py data/sample.csv --threshold 30
"""

from __future__ import annotations

import argparse
import csv
import sys

from phishguard import InvalidURLError, analyze_url


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path")
    parser.add_argument("--threshold", type=int, default=30,
                        help="score a partir del cual se considera phishing (default 30 = sospechoso)")
    parser.add_argument("--show-errors", action="store_true", help="lista falsos positivos y negativos")
    args = parser.parse_args()

    tp = fp = tn = fn = skipped = 0
    mistakes: list[tuple[str, str, int]] = []
    with open(args.csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                score = analyze_url(row["url"]).score
            except InvalidURLError:
                skipped += 1
                continue
            predicted = score >= args.threshold
            actual = row["label"].strip() == "1"
            if predicted and actual:
                tp += 1
            elif predicted:
                fp += 1
                mistakes.append(("FP", row["url"], score))
            elif actual:
                fn += 1
                mistakes.append(("FN", row["url"], score))
            else:
                tn += 1

    total = tp + fp + tn + fn
    if total == 0:
        print("No hay filas válidas en el CSV.", file=sys.stderr)
        return 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    print(f"URLs evaluadas: {total} (omitidas: {skipped})  umbral: {args.threshold}")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Exactitud: {(tp + tn) / total:.3f}")
    print(f"Precisión: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")
    if args.show_errors:
        for kind, url, score in mistakes:
            print(f"  {kind}  {score:>3}  {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
