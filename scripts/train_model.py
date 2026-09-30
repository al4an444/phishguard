"""Train the domain-level ML model and export it as JSON.

Data sources (downloaded into data/raw/, not committed):
  - Legitimate: Tranco top-1M list (https://tranco-list.eu), sampled uniformly across all ranks
    so the model does not simply learn "popular = legitimate".
  - Phishing: Phishing.Database active domains (aggregates PhishTank, OpenPhish and others,
    https://github.com/Phishing-Database/Phishing.Database) plus the OpenPhish community feed.

Label cleaning: phishing entries whose registrable domain appears anywhere in the Tranco list are
dropped (they are compromised or abused legitimate sites, not attacker-registered domains), as are
official brand domains. Data is deduplicated by registrable domain before the train/test split,
so the same domain never appears in both sets.

    pip install -e ".[train]"
    python scripts/train_model.py
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
import sys
import time
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

import numpy as np
import tldextract
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from phishguard.brands import OFFICIAL_DOMAINS
from phishguard.ml import N_FEATURES, NGRAM_SIZES, NUMERIC_FEATURES, DomainModel, domain_features

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
MODEL_PATH = ROOT / "src" / "phishguard" / "model" / "model.json"

SOURCES = {
    "tranco.zip": "https://tranco-list.eu/top-1m.csv.zip",
    "phishing_database.txt":
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "openphish.txt": "https://openphish.com/feed.txt",
}

extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def download(refresh: bool) -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        path = RAW_DIR / name
        if path.exists() and not refresh:
            continue
        print(f"Descargando {url}")
        request = urllib.request.Request(url, headers={"User-Agent": "phishguard-trainer"})
        with urllib.request.urlopen(request, timeout=120) as response:
            path.write_bytes(response.read())


def split_domain(host: str) -> tuple[str, str] | None:
    host = host.strip().lower().rstrip(".")
    if not host or host.startswith("#"):
        return None
    ext = extract(host)
    if not ext.domain or not ext.suffix:
        return None
    return ext.domain, ext.suffix


def load_tranco() -> list[str]:
    with zipfile.ZipFile(RAW_DIR / "tranco.zip") as archive:
        with archive.open(archive.namelist()[0]) as fh:
            reader = csv.reader(io.TextIOWrapper(fh, encoding="utf-8"))
            return [row[1].strip().lower() for row in reader if len(row) >= 2]


def load_phishing_hosts() -> list[str]:
    hosts = (RAW_DIR / "phishing_database.txt").read_text(encoding="utf-8", errors="replace").splitlines()
    for line in (RAW_DIR / "openphish.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if "://" in line:
            hosts.append(line.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].split("@")[-1])
    return hosts


def build_matrix(domains: list[tuple[str, str]]) -> csr_matrix:
    rows, cols, values = [], [], []
    for row, (label, suffix) in enumerate(domains):
        for col, value in domain_features(label, suffix).items():
            rows.append(row)
            cols.append(col)
            values.append(value)
    return csr_matrix((values, (rows, cols)), shape=(len(domains), N_FEATURES), dtype=np.float64)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--refresh", action="store_true", help="volver a descargar los datos")
    parser.add_argument("--legit-sample", type=int, default=200_000)
    parser.add_argument("--max-phishing", type=int, default=200_000)
    parser.add_argument("--C", type=float, default=0.5, help="inversa de la regularización L2")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    started = time.time()

    download(args.refresh)

    tranco = load_tranco()
    tranco_set = set(tranco)
    print(f"Tranco: {len(tranco):,} dominios")

    legit: dict[str, tuple[str, str]] = {}
    for host in rng.sample(tranco, min(args.legit_sample, len(tranco))):
        parts = split_domain(host)
        if parts:
            legit[f"{parts[0]}.{parts[1]}"] = parts

    phishing: dict[str, tuple[str, str]] = {}
    dropped = 0
    for host in load_phishing_hosts():
        parts = split_domain(host)
        if not parts:
            continue
        registered = f"{parts[0]}.{parts[1]}"
        if registered in tranco_set or registered in OFFICIAL_DOMAINS or registered in legit:
            dropped += 1
            continue
        phishing[registered] = parts
    phishing_items = list(phishing.values())
    rng.shuffle(phishing_items)
    phishing_items = phishing_items[:args.max_phishing]
    print(f"Legítimos: {len(legit):,}  Phishing: {len(phishing_items):,}  "
          f"(descartados por aparecer en Tranco u oficiales: {dropped:,})")

    domains = list(legit.values()) + phishing_items
    labels = np.array([0] * len(legit) + [1] * len(phishing_items))
    X = build_matrix(domains)
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, stratify=labels, random_state=args.seed)

    classifier = LogisticRegression(C=args.C, class_weight="balanced", max_iter=3000, solver="liblinear")
    classifier.fit(X_train, y_train)

    proba = classifier.predict_proba(X_test)[:, 1]
    metrics = {}
    for threshold in (0.5, 0.8, 0.9):
        predicted = (proba >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, predicted).ravel()
        metrics[str(threshold)] = {
            "precision": round(float(precision_score(y_test, predicted)), 4),
            "recall": round(float(recall_score(y_test, predicted)), 4),
            "f1": round(float(f1_score(y_test, predicted)), 4),
            "false_positive_rate": round(float(fp / (fp + tn)), 4),
        }
    roc_auc = round(float(roc_auc_score(y_test, proba)), 4)

    coefficients = classifier.coef_[0]
    weights = {str(i): round(float(w), 5) for i, w in enumerate(coefficients) if abs(w) >= 1e-5}
    model_data = {
        "weights": weights,
        "bias": round(float(classifier.intercept_[0]), 5),
        "metadata": {
            "trained_on": date.today().isoformat(),
            "algorithm": "logistic_regression",
            "features": {"ngram_sizes": list(NGRAM_SIZES), "buckets": N_FEATURES - len(NUMERIC_FEATURES),
                         "numeric": list(NUMERIC_FEATURES)},
            "samples": {"legitimate": len(legit), "phishing": len(phishing_items),
                        "train": int(X_train.shape[0]), "test": int(X_test.shape[0])},
            "sources": ["Tranco top-1M", "Phishing.Database (active domains)", "OpenPhish feed"],
            "test_metrics": {"roc_auc": roc_auc, "by_threshold": metrics},
        },
    }

    # Round-trip through the runtime loader to make sure the exported model matches sklearn.
    runtime = DomainModel.from_dict(model_data)
    for label, suffix in domains[:200]:
        expected = classifier.predict_proba(build_matrix([(label, suffix)]))[0, 1]
        assert abs(runtime.predict_proba(label, suffix) - expected) < 1e-3, (label, suffix)

    top_sites = [p for p in (split_domain(h) for h in tranco[:1000]) if p]
    flagged = [f"{lbl}.{sfx}" for lbl, sfx in top_sites if runtime.predict_proba(lbl, sfx) >= 0.8]
    model_data["metadata"]["top1000_flagged_at_0.8"] = len(flagged)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model_data, separators=(",", ":")), encoding="utf-8")

    print(f"\nROC AUC: {roc_auc}")
    for threshold, values in metrics.items():
        print(f"umbral {threshold}: {values}")
    print(f"Top-1000 de Tranco marcados con p>=0.8: {len(flagged)} {flagged[:10]}")
    print(f"Modelo guardado en {MODEL_PATH.relative_to(ROOT)} "
          f"({MODEL_PATH.stat().st_size / 1024:.0f} KB) en {time.time() - started:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
