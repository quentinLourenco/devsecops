#!/usr/bin/env python3
"""
generate-report.py
Génère un rapport HTML enrichi à partir des fichiers JSON Trivy.
"""

import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ── Palette de sévérités ─────────────────────────────────────────────────────
SEVERITY_CONFIG = {
    "CRITICAL": {"color": "#E24B4A", "bg": "#FCEBEB", "icon": "💀", "order": 0},
    "HIGH":     {"color": "#BA7517", "bg": "#FAEEDA", "icon": "🔴", "order": 1},
    "MEDIUM":   {"color": "#185FA5", "bg": "#E6F1FB", "icon": "🟡", "order": 2},
    "LOW":      {"color": "#3B6D11", "bg": "#EAF3DE", "icon": "🟢", "order": 3},
    "UNKNOWN":  {"color": "#5F5E5A", "bg": "#F1EFE8", "icon": "⚪", "order": 4},
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport de Sécurité Trivy — {commit_short}</title>
<style>
  :root {{
    --c-bg: #f8f7f3;
    --c-surface: #ffffff;
    --c-border: rgba(0,0,0,0.10);
    --c-text: #1a1a18;
    --c-muted: #6b6a63;
    --c-critical: #E24B4A;
    --c-high: #BA7517;
    --c-medium: #185FA5;
    --c-low: #3B6D11;
    --c-unknown: #5F5E5A;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--c-bg);
    color: var(--c-text);
    font-size: 14px;
    line-height: 1.6;
  }}
  .header {{
    background: #1a1a18;
    color: #f8f7f3;
    padding: 32px 40px;
    border-bottom: 3px solid #E24B4A;
  }}
  .header h1 {{ font-size: 22px; font-weight: 600; letter-spacing: -0.3px; }}
  .header .meta {{ margin-top: 8px; font-size: 12px; color: #9c9a92; display: flex; gap: 24px; flex-wrap: wrap; }}
  .header .meta span {{ display: flex; align-items: center; gap: 4px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}

  /* Summary cards */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
  }}
  .summary-card {{
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    border-top: 3px solid;
  }}
  .summary-card .count {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .summary-card .label {{ font-size: 11px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; margin-top: 6px; color: var(--c-muted); }}

  /* Scan sections */
  .scan-section {{
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .scan-header {{
    padding: 14px 20px;
    background: #f1efe8;
    border-bottom: 1px solid var(--c-border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    user-select: none;
  }}
  .scan-header h2 {{ font-size: 15px; font-weight: 600; }}
  .scan-header .badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  .badge {{
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }}
  .scan-body {{ overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th {{
    padding: 10px 16px;
    background: #faf9f5;
    font-weight: 600;
    text-align: left;
    border-bottom: 1px solid var(--c-border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--c-muted);
  }}
  td {{
    padding: 10px 16px;
    border-bottom: 1px solid rgba(0,0,0,0.05);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #faf9f5; }}
  .sev-chip {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }}
  .cve-link {{
    color: var(--c-medium);
    text-decoration: none;
    font-weight: 500;
  }}
  .cve-link:hover {{ text-decoration: underline; }}
  .fixed-in {{ color: var(--c-low); font-size: 12px; }}
  .no-fix {{ color: var(--c-muted); font-size: 12px; font-style: italic; }}
  .empty-scan {{ padding: 20px; color: var(--c-muted); text-align: center; font-style: italic; }}
  .collapsible {{ display: block; }}
  .toggle-btn {{ background: none; border: none; cursor: pointer; font-size: 16px; }}
  footer {{
    text-align: center;
    padding: 24px;
    color: var(--c-muted);
    font-size: 12px;
    border-top: 1px solid var(--c-border);
    margin-top: 40px;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔒 Rapport de Sécurité Trivy</h1>
  <div class="meta">
    <span>📅 {generated_at}</span>
    <span>🔀 Commit: <code style="background:rgba(255,255,255,0.1);padding:1px 5px;border-radius:3px">{commit_short}</code></span>
    <span>🌿 Branche: <strong>{branch}</strong></span>
    <span>🏃 Run: #{run_id}</span>
  </div>
</div>

<div class="container">

  <!-- Summary cards -->
  <div class="summary-grid">
    {summary_cards}
  </div>

  <!-- Per-scan sections -->
  {scan_sections}

</div>

<footer>
  Généré automatiquement par le pipeline CI/CD · Trivy Security Scanner
  · <a href="https://trivy.dev" style="color:#185FA5">trivy.dev</a>
</footer>

<script>
document.querySelectorAll('.scan-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    body.style.display = body.style.display === 'none' ? 'block' : 'none';
    h.querySelector('.toggle-btn').textContent =
      body.style.display === 'none' ? '▶' : '▼';
  }});
}});
</script>
</body>
</html>"""


def load_results(results_dir: Path) -> dict:
    """Charge tous les fichiers JSON Trivy d'un répertoire."""
    results = {}
    for f in sorted(results_dir.glob("trivy-*.json")):
        try:
            with open(f) as fp:
                data = json.load(fp)
            # Nom lisible depuis le nom de fichier
            name = f.stem.replace("trivy-", "").replace("-results", "")
            results[name] = data
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠️  Impossible de lire {f}: {e}", file=sys.stderr)
    return results


def extract_vulns(data: dict) -> list:
    """Extrait toutes les CVE d'un résultat Trivy."""
    vulns = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            vulns.append({
                "target": target,
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "vuln_id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title", v.get("Description", "")[:80]),
                "cvss": v.get("CVSS", {}).get("nvd", {}).get("V3Score", ""),
            })
    return vulns


def count_by_severity(vulns: list) -> dict:
    counts = defaultdict(int)
    for v in vulns:
        counts[v["severity"]] += 1
    return counts


def severity_badge(sev: str) -> str:
    cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["UNKNOWN"])
    return (
        f'<span class="sev-chip" '
        f'style="background:{cfg["bg"]};color:{cfg["color"]}">'
        f'{cfg["icon"]} {sev}</span>'
    )


def build_scan_section(name: str, vulns: list) -> str:
    counts = count_by_severity(vulns)
    badges = "".join(
        f'<span class="badge" style="background:{SEVERITY_CONFIG[s]["bg"]};'
        f'color:{SEVERITY_CONFIG[s]["color"]}">'
        f'{SEVERITY_CONFIG[s]["icon"]} {counts[s]} {s}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        if counts.get(s, 0) > 0
    )
    if not badges:
        badges = '<span class="badge" style="background:#EAF3DE;color:#3B6D11">✅ Clean</span>'

    if not vulns:
        body = '<div class="empty-scan">✅ Aucune vulnérabilité détectée pour ce composant.</div>'
    else:
        rows = ""
        sorted_vulns = sorted(
            vulns,
            key=lambda v: SEVERITY_CONFIG.get(v["severity"], {"order": 99})["order"]
        )
        for v in sorted_vulns:
            cve_url = f"https://nvd.nist.gov/vuln/detail/{v['vuln_id']}"
            fixed = (
                f'<span class="fixed-in">🔧 {v["fixed"]}</span>'
                if v["fixed"]
                else '<span class="no-fix">pas de fix</span>'
            )
            cvss = f'<code style="font-size:12px">{v["cvss"]}</code>' if v["cvss"] else "—"
            rows += f"""<tr>
              <td>{severity_badge(v['severity'])}</td>
              <td><a class="cve-link" href="{cve_url}" target="_blank">{v['vuln_id']}</a></td>
              <td><strong>{v['pkg']}</strong><br><small style="color:#6b6a63">{v['target']}</small></td>
              <td><code style="font-size:12px">{v['installed']}</code></td>
              <td>{fixed}</td>
              <td>{cvss}</td>
              <td style="max-width:280px;font-size:12px;color:#6b6a63">{v['title']}</td>
            </tr>"""
        body = f"""<table>
          <thead><tr>
            <th>Sévérité</th><th>CVE</th><th>Paquet / Cible</th>
            <th>Version installée</th><th>Fix disponible</th>
            <th>CVSS v3</th><th>Description</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    total = len(vulns)
    title = name.upper().replace("-", " ")
    return f"""
<div class="scan-section">
  <div class="scan-header">
    <h2>📦 {title} <span style="font-weight:400;color:#6b6a63;font-size:13px">({total} vuln.)</span></h2>
    <div style="display:flex;align-items:center;gap:10px">
      <div class="badges">{badges}</div>
      <button class="toggle-btn" aria-label="toggle">▼</button>
    </div>
  </div>
  <div class="collapsible scan-body">{body}</div>
</div>"""


def build_summary_cards(all_vulns: list) -> str:
    total_counts = defaultdict(int)
    for v in all_vulns:
        total_counts[v["severity"]] += 1

    cards = f"""<div class="summary-card" style="border-top-color:#888;border-left:none">
      <div class="count">{len(all_vulns)}</div>
      <div class="label">Total</div>
    </div>"""

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        cfg = SEVERITY_CONFIG[sev]
        n = total_counts.get(sev, 0)
        cards += f"""<div class="summary-card" style="border-top-color:{cfg['color']}">
          <div class="count" style="color:{cfg['color']}">{n}</div>
          <div class="label">{cfg['icon']} {sev}</div>
        </div>"""

    return cards


def main():
    parser = argparse.ArgumentParser(description="Génère un rapport HTML Trivy")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", default="security-report.html")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--run-id", default="—")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    results = load_results(results_dir)

    all_vulns = []
    scan_sections_html = ""

    for name, data in results.items():
        vulns = extract_vulns(data)
        all_vulns.extend(vulns)
        if not args.summary_only:
            scan_sections_html += build_scan_section(name, vulns)

    if args.summary_only:
        # Résumé console pour GITHUB_STEP_SUMMARY (via summary-to-github.py)
        counts = count_by_severity(all_vulns)
        print(f"## 🔒 Résumé de sécurité Trivy\n")
        print(f"| Sévérité | Nombre |")
        print(f"|----------|--------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            cfg = SEVERITY_CONFIG[sev]
            print(f"| {cfg['icon']} {sev} | **{counts.get(sev, 0)}** |")
        print(f"\n> Total : **{len(all_vulns)}** vulnérabilités · "
              f"commit `{args.commit[:8]}` · branche `{args.branch}`")
        return

    html = HTML_TEMPLATE.format(
        generated_at=datetime.utcnow().strftime("%d/%m/%Y à %H:%M UTC"),
        commit_short=args.commit[:8],
        branch=args.branch,
        run_id=args.run_id,
        summary_cards=build_summary_cards(all_vulns),
        scan_sections=scan_sections_html,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ Rapport généré : {args.output} ({len(all_vulns)} vulnérabilités)")


if __name__ == "__main__":
    main()
