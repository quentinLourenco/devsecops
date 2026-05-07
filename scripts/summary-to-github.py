#!/usr/bin/env python3
"""
summary-to-github.py
Génère le contenu Markdown pour GITHUB_STEP_SUMMARY.
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict

SEVERITY_CONFIG = {
    "CRITICAL": {"icon": "💀", "order": 0},
    "HIGH":     {"icon": "🔴", "order": 1},
    "MEDIUM":   {"icon": "🟡", "order": 2},
    "LOW":      {"icon": "🟢", "order": 3},
    "UNKNOWN":  {"icon": "⚪", "order": 4},
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--commit", default="unknown")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    per_source = {}
    global_counts = defaultdict(int)
    total = 0

    for f in sorted(results_dir.glob("trivy-*.json")):
        try:
            with open(f) as fp:
                data = json.load(fp)
        except Exception:
            continue

        name = f.stem.replace("trivy-", "").replace("-results", "").upper()
        counts = defaultdict(int)
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []) or []:
                sev = v.get("Severity", "UNKNOWN")
                counts[sev] += 1
                global_counts[sev] += 1
                total += 1
        per_source[name] = dict(counts)

    # Header
    status_icon = "🚨" if global_counts.get("CRITICAL", 0) > 0 else (
                  "⚠️" if global_counts.get("HIGH", 0) > 0 else "✅")
    print(f"## {status_icon} Rapport de Sécurité Trivy\n")
    print(f"> Commit `{args.commit[:8]}` · {total} vulnérabilité(s) détectée(s) au total\n")

    # Tableau global
    print("### 📊 Résumé global\n")
    print("| Sévérité | Count |")
    print("|----------|------:|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        cfg = SEVERITY_CONFIG[sev]
        n = global_counts.get(sev, 0)
        bold = "**" if n > 0 and sev in ("CRITICAL", "HIGH") else ""
        print(f"| {cfg['icon']} {sev} | {bold}{n}{bold} |")
    print(f"| **TOTAL** | **{total}** |\n")

    # Tableau par composant
    print("### 📦 Détail par composant\n")
    headers = ["Composant"] + [f"{SEVERITY_CONFIG[s]['icon']} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]]
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join(["---"] * len(headers)) + "|")
    for src, counts in per_source.items():
        row = [src]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = counts.get(sev, 0)
            row.append(f"**{n}**" if n > 0 and sev in ("CRITICAL", "HIGH") else str(n))
        print("| " + " | ".join(row) + " |")

    print("\n---")
    print("📄 Le rapport HTML détaillé est disponible dans les **Artifacts** du workflow.")
    print("🛡️ Les CVE ont été transmises au **GitHub Security Center** (onglet Security).")

    if global_counts.get("CRITICAL", 0) > 0:
        print(f"\n> 🚨 **Action requise** : {global_counts['CRITICAL']} vulnérabilité(s) CRITIQUE(S) détectée(s). Mise à jour immédiate recommandée.")


if __name__ == "__main__":
    main()
