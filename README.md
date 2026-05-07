# 🚀 WordPress + Monitoring Stack avec Pipeline de Sécurité Trivy

[![Security Scan](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/pipeline.yml/badge.svg)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/pipeline.yml)

Stack complète WordPress + monitoring (Prometheus/Grafana) avec pipeline CI/CD intégrant
un scan de sécurité Trivy, génération de rapports HTML et intégration GitHub Security Center.

## 📐 Architecture de la pipeline

```
push/PR → [Deploy Stack] → [Trivy Scan x5] → [Rapport HTML] + [Upload SARIF GitHub Security]
```

## 🔧 Prérequis

- Docker & Docker Compose v2
- Compte GitHub avec Actions activé
- (Optionnel) GitHub Advanced Security pour le Code Scanning

## ⚙️ Configuration

### Secrets GitHub requis

Aller dans **Settings → Secrets and variables → Actions** et créer :

| Secret | Description |
|--------|-------------|
| `WORDPRESS_DB_PASSWORD` | Mot de passe BDD WordPress |
| `MYSQL_ROOT_PASSWORD` | Mot de passe root MySQL |
| `GRAFANA_ADMIN_PASSWORD` | Mot de passe admin Grafana |

### Lancement local

```bash
cp .env.example .env
# Editer .env avec vos mots de passe
docker compose up -d
```

Services accessibles :
- WordPress : http://localhost:8080
- Grafana : http://localhost:3000 (admin / votre mot de passe)
- Prometheus : http://localhost:9090

## 🔒 Pipeline de sécurité

### Jobs

| Job | Description |
|-----|-------------|
| `deploy-stack` | Build image WP + validation docker-compose |
| `trivy-scan` | 5 scans Trivy (fs + 4 images Docker) |
| `trivy-report` | Génération rapport HTML + résumé GitHub |
| `upload-sarif` | Upload SARIF → GitHub Security Center |

### Composants scannés

- **Filesystem** : tout le code du repo (IaC, configs, secrets)
- **wordpress:latest** : image officielle WordPress
- **mysql:8.0** : image MySQL
- **prom/prometheus:latest** : image Prometheus
- **grafana/grafana:latest** : image Grafana

### Rapport HTML

Disponible dans **Actions → Artifacts → security-report-html**

### GitHub Security Center

Les CVE sont automatiquement transmises à l'onglet **Security → Code Scanning Alerts**
avec mapping de sévérité CVSS → GitHub (CRITICAL/HIGH → error, MEDIUM → warning, LOW → note).

## 📁 Structure

```
.
├── .github/workflows/
│   └── pipeline.yml          # Pipeline CI/CD complète
├── docker/
│   └── Dockerfile.wordpress  # Image WP durcie
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml    # Config scraping
│   └── grafana/
│       ├── provisioning/     # Auto-config datasources & dashboards
│       └── dashboards/       # Dashboards JSON
├── scripts/
│   ├── generate-report.py    # Génération rapport HTML
│   ├── json-to-sarif.py      # Conversion JSON → SARIF
│   └── summary-to-github.py  # Résumé GITHUB_STEP_SUMMARY
└── docker-compose.yml
```

## 🛡️ Valeur ajoutée sécurité

- **5 scans** couvrant tous les composants de la stack
- **Rapport HTML** avec filtrage par sévérité, liens CVE, fix disponible
- **SARIF upload** → intégration native GitHub Security, PR annotations
- **Scan hebdomadaire** automatique (cron lundi 2h)
- **Artifacts 90 jours** pour audit trail

## 📄 Licence

MIT
