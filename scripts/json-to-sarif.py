#!/usr/bin/env python3
"""
json-to-sarif.py
Convertit les résultats JSON Trivy en format SARIF 2.1.0
pour upload vers GitHub Code Scanning (Security tab).
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "UNKNOWN":  "none",
}

SECURITY_LEVEL_MAP = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "UNKNOWN":  0.0,
}


def load_results(results_dir: Path) -> dict:
    results = {}
    for f in sorted(results_dir.glob("trivy-*.json")):
        try:
            with open(f) as fp:
                data = json.load(fp)
            name = f.stem.replace("trivy-", "").replace("-results", "")
            results[name] = data
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️  Cannot read {f}: {e}", file=sys.stderr)
    return results


def build_rules(all_vulns: list) -> tuple[list, dict]:
    """Construit la liste des règles SARIF (une par CVE unique)."""
    seen = {}
    rules = []
    for v in all_vulns:
        vid = v.get("VulnerabilityID", "UNKNOWN")
        if vid in seen:
            continue
        seen[vid] = len(rules)
        sev = v.get("Severity", "UNKNOWN")
        desc = v.get("Description", v.get("Title", "No description available."))
        refs = []
        if v.get("References"):
            refs = [{"text": r, "url": r} for r in v["References"][:3]]
        rule = {
            "id": vid,
            "name": f"Vulnerability{vid.replace('-', '')}",
            "shortDescription": {"text": v.get("Title", vid)[:128]},
            "fullDescription": {"text": desc[:512] if desc else vid},
            "defaultConfiguration": {
                "level": SEVERITY_MAP.get(sev, "none")
            },
            "properties": {
                "tags": ["security", "supply-chain", sev.lower()],
                "precision": "high",
                "security-severity": str(SECURITY_LEVEL_MAP.get(sev, 0.0)),
            },
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{vid}",
        }
        if refs:
            rule["help"] = {
                "text": "\n".join(r["url"] for r in refs),
                "markdown": "\n".join(f"- [{r['url']}]({r['url']})" for r in refs),
            }
        rules.append(rule)
    return rules, seen


def build_results(all_scan_data: list, rule_index: dict) -> list:
    """Construit la liste des résultats SARIF."""
    sarif_results = []
    for source, vuln, result_target in all_scan_data:
        vid = vuln.get("VulnerabilityID", "UNKNOWN")
        sev = vuln.get("Severity", "UNKNOWN")
        pkg = vuln.get("PkgName", "unknown-pkg")
        installed = vuln.get("InstalledVersion", "?")
        fixed = vuln.get("FixedVersion", "")
        title = vuln.get("Title", vid)

        message_text = (
            f"Package `{pkg}` version `{installed}` is affected by {vid} ({sev}). "
        )
        if fixed:
            message_text += f"Fix available in version `{fixed}`."
        else:
            message_text += "No fix available yet."

        # Localisation : on pointe vers le Dockerfile ou docker-compose si dispo
        uri = "docker-compose.yml"
        if "wordpress" in source.lower():
            uri = "docker/Dockerfile.wordpress"
        elif "prometheus" in source.lower() or "grafana" in source.lower() or "mysql" in source.lower():
            uri = "docker-compose.yml"
        else:
            uri = "."  # filesystem scan

        r = {
            "ruleId": vid,
            "ruleIndex": rule_index.get(vid, 0),
            "level": SEVERITY_MAP.get(sev, "none"),
            "message": {"text": message_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {"startLine": 1}
                },
                "logicalLocations": [{
                    "name": pkg,
                    "kind": "package",
                }]
            }],
            "fingerprints": {
                "primaryLocationLineHash": f"{vid}:{pkg}:{installed}:0",
            },
            "properties": {
                "severity": sev,
                "package": pkg,
                "installedVersion": installed,
                "fixedVersion": fixed,
                "source": source,
            }
        }
        sarif_results.append(r)
    return sarif_results


def main():
    parser = argparse.ArgumentParser(description="Convert Trivy JSON to SARIF")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", default="trivy-combined.sarif")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    all_results = load_results(results_dir)

    # Collecter toutes les vulnérabilités
    all_vulns_flat = []
    all_scan_data = []  # (source_name, vuln_dict, target)

    for source_name, data in all_results.items():
        for result in data.get("Results", []):
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []) or []:
                all_vulns_flat.append(v)
                all_scan_data.append((source_name, v, target))

    print(f"📊 {len(all_vulns_flat)} vulnérabilités trouvées dans {len(all_results)} scans")

    rules, rule_index = build_rules(all_vulns_flat)
    sarif_results = build_results(all_scan_data, rule_index)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Trivy",
                    "version": "latest",
                    "informationUri": "https://trivy.dev",
                    "rules": rules,
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
            "columnKind": "utf16CodeUnits",
        }]
    }

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2, ensure_ascii=False)

    print(f"✅ SARIF généré : {output_path}")
    print(f"   → {len(rules)} règles, {len(sarif_results)} résultats")


if __name__ == "__main__":
    main()
