
<div align="center">

# ParaKang ASM v1.9

## Integrated Penetration Testing & Reconnaissance Automation Platform

<p>
  <a href="#"><img alt="Python" src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square"/></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/></a>
  <a href="#"><img alt="Security" src="https://img.shields.io/badge/Security-Hardened-brightgreen?style=flat-square"/></a>
  <a href="#"><img alt="Penetration Testing" src="https://img.shields.io/badge/Penetration_Testing-Advanced-red?style=flat-square"/></a>
  <a href="#"><img alt="Security Tools" src="https://img.shields.io/badge/Security_Tools-150+-orange?style=flat-square"/></a>
  <a href="#"><img alt="AI Agents" src="https://img.shields.io/badge/AI_Agents-12+-blueviolet?style=flat-square"/></a>
</p>

**Advanced AI-powered penetration testing framework with 150+ integrated security tools and 12+ autonomous AI agents**

---

## Quick Navigation

📚 [What's New](#whats-new) • 🏗️ [Architecture](#system-architecture) • 🚀 [Installation](#quick-start) • ✨ [Features](#key-capabilities) • 🤖 [AI Agents](#ai-powered-features) • 📖 [API Reference](#rest-api-reference)

## Follow Our Community

[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?style=flat-square&logo=discord)](https://discord.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com)

---

</div>

## Table of Contents

- [Executive Summary](#executive-summary)
- [Quick Start](#quick-start)
- [Initial Configuration](#initial-configuration)
- [User Management & Authentication](#user-management--authentication)
- [Usage Guide](#usage-guide)
- [System Architecture](#system-architecture)
- [Integrated Tools List](#integrated-tools-list)
- [Dynamic Proxy System](#dynamic-proxy-system)
- [Nuclei & DAST Templates](#nuclei--dast-templates)
- [REST API Reference](#rest-api-reference)
- [Full Installation](#full-installation)
- [Troubleshooting](#troubleshooting)
- [Update History](#update-history)

---

## Executive Summary

ParaKang provides integrated orchestration of 25+ reconnaissance and vulnerability assessment tools in Docker containers with Celery coordination for large-scale parallel execution.

### Key Capabilities

- **Active Discovery**: Subdomain enumeration from 7 different sources, port scanning (naabu), HTTP probing (httpx), technology detection (Wappalyzer)
- **Intelligence Gathering**: HUMINT (GitHub org enumeration, LinkedIn employee discovery, job posting analysis), SIGINT (ASN/BGP enumeration, email security audit, TLS certificate analysis, passive intelligence via Shodan/Censys/InternetDB)
- **Vulnerability Assessment**: Nuclei DAST templates (249+ templates), reflected XSS detection (dalfox), CRLF injection (crlfuzz), S3 bucket misconfiguration, WAF detection (wafw00f)
- **Advanced Reporting**: LLM-enhanced vulnerability descriptions with OpenAI and local Ollama support, CVSS tracking, HackerOne integration
- **Advanced Features**: Dynamic proxy rotation from 4 public sources, subscan targeting, intelligent de-duplication, role-based access control, webhook notifications (Slack/Discord/Telegram)

### Security Enhancements in Custom Edition

- 27 security remediations from deep audit (2 CRITICAL, 7 HIGH, 10 MEDIUM, 8 LOW)
- Improved LLM integration for vulnerability reporting
- Comprehensive DAST templates with granular false-positive control
- Proxy hardening with IP blocking detection and automatic fallback
- Dynamic Ollama model selection for maximum flexibility

---

## Quick Start

### System Requirements

```
Operating System:  Ubuntu 20.04+ / Debian / Kali Linux
Docker:            20.10+ with Docker Compose 2.0+
RAM:               Minimum 4 GB (recommended 8 GB+)
Disk:              Minimum 20 GB for scan results and models
Network:           Internet (for downloading tools and models)
Root Access:       Required for installation (sudo)
```

### Quick Installation (3 Steps)

**Step 1: Prepare Repository**
```bash
# Clone and enter directory
git clone <repository-url> paraKang-Custom
cd paraKang-Custom

# Copy and configure environment
cp .env.example .env

# Edit .env with your favorite text editor
# Change: POSTGRES_PASSWORD, REDIS_PASSWORD
nano .env
```

**Step 2: Run Installer**
```bash
# Interactive mode (recommended for first-time setup)
sudo ./install.sh

# Or automated mode (non-interactive)
sudo ./install.sh -n
```

This process will:
- ✓ Verify Docker installation
- ✓ Build container images (web, celery, database, redis)
- ✓ Initialize PostgreSQL database
- ✓ Run Django migrations
- ✓ Setup first admin user (via prompt or .env)
- ✓ Prepare Ollama container for LLM (optional)

**Step 3: Access Application**
```bash
# Verify all containers are running
docker compose ps

# Access in browser
# HTTP (development):  http://localhost
# HTTPS (production):  https://localhost (with self-signed cert)
# API endpoint:        http://localhost:8000/api/
```

**Initial Login:**
- Username: `admin` (or your `DJANGO_SUPERUSER_USERNAME` from .env)
- Password: Your `DJANGO_SUPERUSER_PASSWORD` from .env

---

## Initial Configuration

### Important Environment Variables

Edit `.env` before running `install.sh`:

| Variable | Default | Description |
|----------|---------|-----------|
| `POSTGRES_PASSWORD` | - | **REQUIRED** - Change from .env.example |
| `REDIS_PASSWORD` | - | **REQUIRED** - Change from .env.example |
| `DOMAIN_NAME` | `localhost` | Hostname for application (production: your domain) |
| `DEBUG` | `0` | Do not change to `1` in production |
| `DJANGO_SUPERUSER_USERNAME` | `admin` | First admin username |
| `DJANGO_SUPERUSER_PASSWORD` | - | Admin password (auto-generate if empty) |
| `DJANGO_SUPERUSER_EMAIL` | `admin@localhost` | Admin email |
| `MIN_CONCURRENCY` | `10` | Minimum active Celery workers |
| `MAX_CONCURRENCY` | `30` | Maximum parallel workers (adjust with RAM) |
| `GUNICORN_WORKERS` | `4` | Django worker processes |
| `GUNICORN_THREADS` | `2` | Thread per worker |

**Recommended Concurrency Based on RAM:**
```
4 GB RAM:   MIN_CONCURRENCY=5,  MAX_CONCURRENCY=10
8 GB RAM:   MIN_CONCURRENCY=10, MAX_CONCURRENCY=30
16 GB RAM:  MIN_CONCURRENCY=20, MAX_CONCURRENCY=50
32 GB RAM:  MIN_CONCURRENCY=30, MAX_CONCURRENCY=100
```

### External API Integration (Optional)

After logging into Dashboard → Settings → API Vault, configure API keys:

| Service | Configuration | Usage |
|---------|----------|----------|
| **OpenAI** | API Key | LLM for vulnerability description (recommended: gpt-3.5-turbo or gpt-4) |
| **Ollama** | Auto-detect (port 11434) | Local offline LLM (alternative to OpenAI) |
| **Shodan** | API Key | Passive intelligence (open ports, CVEs, services) |
| **Censys** | API ID + Secret | IP geolocation, certificate analysis |
| **Netlas** | API Key | Subdomain and certificate enumeration |
| **HackerOne** | Username + API Key | Sync bug bounty programs |
| **Slack / Discord / Telegram** | Webhook URL | Scan completion notifications |

### Proxy Setup (Optional)

```bash
# Manual: Dashboard → Settings → Proxy
# Setup: Enter local proxy IP:PORT if available

# Automatic: Free public proxies fetched every 7 days
# Check schedule at Dashboard → Activity Logs
```

---

## User Management & Authentication

### Role and Permission Structure

ParaKang has 3 roles with permission hierarchy:

| Role | Access | Description |
|------|--------|-----------|
| **System Administrator** | All features | Full access: system config, all scans, user management, API keys |
| **Penetration Tester** | Scan & Targets | Create/edit targets, run scans, subscan, view results (no system settings access) |
| **Auditor** | Read-only | View scan results and generate reports only (cannot create scans) |

### Creating New Users

**Method 1: Via Django Admin Shell (Recommended)**
```bash
# Access Django admin shell
docker exec parakang-web-1 python manage.py shell

# In Python shell:
from django.contrib.auth import get_user_model
User = get_user_model()

# Create new user
user = User.objects.create_user(
    username='john_pentester',
    email='john@company.com',
    password='SecurePassword123!',
    first_name='John',
    last_name='Doe'
)

# Assign role (using django-role-permissions)
from rolepermissions.roles import assign_role
assign_role(user, 'penetration_tester')

print(f"User created: {user.username} with role: penetration_tester")
exit()
```

**Method 2: Via Django Command (Production)**
```bash
docker exec parakang-web-1 python manage.py createsuperuser \
  --username john_admin \
  --email john@company.com
  
# Follow prompt for password
# Then assign role via Django shell (Method 1)
```

**Method 3: Via Django Admin Web Interface**
```
1. Login to https://localhost/admin/ with admin credentials
2. Navigate to: Users
3. Click: Add User
4. Enter: username, email, password
5. Save
6. Edit newly created user again
7. In group section, assign appropriate role
8. Save
```

### Changing User Password

**User Changes Own Password:**
```
1. Login to application
2. Click profile icon (top-right)
3. Click "Change Password"
4. Enter old and new password
5. Save
```

**Admin Resets User Password:**
```bash
docker exec parakang-web-1 python manage.py shell

from django.contrib.auth import get_user_model
User = get_user_model()

user = User.objects.get(username='john_pentester')
user.set_password('NewSecurePassword123!')
user.save()

print(f"Password reset for {user.username}")
exit()
```

### Managing Roles and Permissions

```bash
# List all users and their roles
docker exec parakang-web-1 python manage.py shell

from django.contrib.auth import get_user_model
from rolepermissions.roles import get_user_roles

User = get_user_model()
for user in User.objects.all():
    roles = get_user_roles(user)
    print(f"{user.username}: {', '.join([r.get_name() for r in roles])}")

exit()
```

### User Preferences per Project

Each user can configure preferences at Dashboard → Settings:

| Setting | Default | Description |
|---------|---------|-----------|
| **Bug Bounty Mode** | Off | Highlight only bug bounty-relevant findings |
| **Notification Preference** | On | Enable/disable notifications |
| **API Token** | Auto-gen | REST API authentication |

---

## Usage Guide

### Creating and Running Scans

**Step 1: Create Project (Logical Container)**
```
Dashboard → Projects → New Project
  Project Name: "PT-Client-ABC"
  Description: "Penetration test for ABC Corporation"
  Create
```

**Step 2: Add Target Domain**
```
Dashboard → Targets (under project) → Add Target
  Domain: example.com
  Organization: ABC Corp (optional)
  In Scope CIDR: 192.0.2.0/24 (for private targets)
  Custom Headers: X-Custom-Header: value
  Save
```

**Step 3: Select Scan Engine and Run**
```
Target detail page → Initiate Scan
  Select Engine: "Full Scan" or custom engine
  Proxy Mode: Auto (use proxy) / Direct (no proxy)
  Intensity: Normal / Aggressive (affects rate limiting)
  Start Scan
```

**Monitoring Scan Progress:**
- Real-time progress bar on Dashboard
- View logs: Activity Logs tab
- Cancel anytime if needed

**Step 4: Review Results**
```
Scan Results → Findings
  Filter by: Severity (Critical/High/Medium/Low)
  Filter by: Type (Subdomain/Endpoint/Vulnerability)
  Export: CSV / JSON / PDF Report
```

### Subscan (Re-scan Specific Target)

For rescanning a domain or subdomain without full scan:

```
Scan Results → Select Subdomain/Domain
  Click: "SubScan"
  Select Type: 
    - Port Scan: naabu + nmap
    - Vulnerability: nuclei + dalfox
    - Screenshot: gowitness
    - Tech Detect: Wappalyzer
  Run
```

### Using Custom Scan Engines

Create YAML engine configuration for specific workflows:

**Dashboard → Scan Engines → Create Custom Engine**

```yaml
# Example: OSINT Only (no active scanning)
name: OSINT Recon
description: Passive intelligence gathering only
enabled: true

discovery:
  subfinder: true
  passive_sources:
    - certspotter
    - crt.sh
  skip_active: true

osint:
  discover: [emails, employees]
  dorks: [login_pages, admin_panels]
  humint:
    github_org: true
    linkedin: true
    job_postings: true
  sigint:
    asn_recon: true
    email_security: true

vulnerability_scan:
  enabled: false
```

### Export and Reporting

**Generate Report:**
```
Scan Results → Export
  Format: PDF / HTML / JSON / CSV
  Include:
    ☑ Executive Summary
    ☑ Technical Findings
    ☑ Screenshots
    ☑ Remediation Guide (LLM-powered)
  Download
```

**API Integration for Custom Reporting:**
```bash
# Fetch all vulnerabilities from specific scan
curl -H "Authorization: Bearer $API_TOKEN" \
  "http://localhost:8000/api/listVulnerability/?scan_id=123"

# Response: JSON array with vulnerability details
```

---

## System Architecture

```
Browser (HTTPS)
    |
    v
Nginx (reverse proxy, TLS termination)
    |
    v
Gunicorn / Django (web + REST API)
    |
    +---> PostgreSQL  (all recon data stored here)
    |
    v
Celery Workers  <---  Redis (message broker + result backend)
    |
    +--- main_scan_queue        : main scan orchestration
    +--- subscan_queue          : per-subdomain subscan
    +--- osint_discovery_queue  : OSINT, HUMINT, SIGINT, theHarvester
    +--- dorking_queue          : Google/Bing dork via GooFuzz
    +--- theHarvester_queue     : email, subdomain, employee harvest
    +--- h8mail_queue           : credential breach check
    +--- vulnerability_scan_queue : nuclei, dalfox, crlfuzz
    +--- (and other queues)
    |
    v
Scan Result Files
    /usr/src/app/scan_results/{domain}/{scan_id}/
```

Scan workflow:

1. User creates target, selects engine, clicks "Initiate Scan"
2. `initiate_scan` (Celery task) creates `ScanHistory`, then builds Celery chord:
   - Parallel group: subdomain discovery, OSINT, port scan
   - After group completes: HTTP crawl, dir/file fuzz, fetch URL
   - Parallel again: vulnerability scan, screenshot, WAF detection
3. Each task saves results directly to PostgreSQL
4. Web interface polls via REST API for live UI updates

---

## Integrated Tools List

| Category | Tool | Description |
|----------|------|-----------|
| Subdomain Discovery | subfinder, ctfr, sublist3r, tlsx, oneforall, netlas, chaos | Enumerate subdomains from various sources |
| HTTP Crawl | httpx | Probe HTTP/HTTPS to all subdomains, get status, headers, title |
| Port Scan | naabu | Fast port scanner; optionally followed by nmap |
| Directory Fuzz | ffuf | Directory and file fuzzing |
| Endpoint Discovery | gospider, hakrawler, waybackurls, katana, gau | Crawl and archive URLs |
| Screenshot | gowitness | Screenshot each live subdomain |
| Vulnerability Scan | nuclei | CVE templates, AI DAST, DAST vulnerabilities (249 custom templates) |
| XSS | dalfox | Reflected and DOM XSS |
| CRLF | crlfuzz | CRLF injection |
| S3 Bucket | s3scanner | Misconfigured S3 detection |
| OSINT | theHarvester | Email, subdomain, employee from Bing, CertSpotter, HunterIO, etc |
| OSINT | h8mail | Credential breach check |
| OSINT Dork | GooFuzz | Google/Bing dork (login pages, admin panels, config files, etc) |
| HUMINT | humint_github_recon | GitHub org recon: members, repos, email from commits, secret detection |
| HUMINT | humint_linkedin_recon | Bing dork site:linkedin.com/in/ for employee enumeration |
| HUMINT | humint_job_postings | Job posting dork: extract tech stack (AWS, K8s, LDAP, etc) |
| SIGINT | sigint_asn_recon | ASN/BGP enumeration via BGPView.io + amass intel |
| SIGINT | sigint_email_security | Audit SPF, DKIM (20 selectors), DMARC + spoofing risk assessment |
| SIGINT | sigint_passive_intel | Shodan/Censys/InternetDB: open ports, CVEs, services per IP |
| SIGINT | sigint_cert_analysis | Direct TLS handshake + CT log (crt.sh), expired/self-signed/SHA1 detection |
| LLM | Ollama / OpenAI GPT | Vulnerability descriptions, impact, remediation, attack surface suggestions |
| WAF | wafw00f | Web Application Firewall detection |
| WHOIS | built-in | Domain registration info |

---

## Dynamic Proxy System

ParaKang-Custom uses proxies to protect your original IP during scanning (especially subdomain discovery, nuclei, fetch URL, and Google dorking). The proxy system is fully automatic — no manual configuration needed when using free proxies.

### Proxy Sources

Proxies are automatically fetched from 4 public sources:

| # | Source | URL | Method |
|---|--------|-----|--------|
| 1 | **proxifly** | `cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/.../data.json` | JSON CDN — most reliable |
| 2 | **proxyscrape** | `api.proxyscrape.com/v3/free-proxy-list/get?protocol=http...` | Plain-text REST API |
| 3 | **free-proxy-list.net** | `https://free-proxy-list.net/` | HTML table scraping |
| 4 | **proxylistfree.com** | `https://www.proxylistfree.com/` | HTML table scraping |

All proxies are stored in `Settings → Proxy` (field `proxies`) in `IP:PORT` format, one entry per line.

### Automatic Workflow (Celery Beat)

```
Worker startup (parakang-celery-1)
    │
    ▼
worker_ready signal (celery.py)
    │
    ▼
Register PeriodicTask to DB:
  name: "Weekly proxy refresh & prune"
  task: fetch_free_proxies
  schedule: every 7 days
    │
    ▼
parakang-celery-beat-1 (DatabaseScheduler)
  polling DB every ~5 seconds
    │
    ▼  [every 7 days]
fetch_free_proxies()
    ├─ Scrape 4 sources → collect new IP:PORT
    ├─ Test all EXISTING proxies in DB
    │   └─ 50 threads, TCP connect timeout 2 seconds
    │       ├─ Alive  → retain
    │       └─ Dead   → remove (pruned)
    ├─ Merge: old proxies still alive + new proxies
    └─ Save to DB
```

**Example refresh log:**
```
fetch_free_proxies: proxifly gave 523 proxies
fetch_free_proxies: proxyscrape added 312
fetch_free_proxies: free-proxy-list added 89
fetch_free_proxies: testing 2039 existing proxies for liveness...
fetch_free_proxies: pruned 1847 dead proxies, 192 still alive
fetch_free_proxies: +968 new, -1847 dead removed, 1160 total in DB
```

### Proxy Selection During Scan (get_random_proxy)

Each time a tool (nuclei, httpx, naabu, etc) needs a proxy, the system:

1. Fetch proxy list from DB
2. Randomize order (`random.shuffle`)
3. Test **batch of 20 proxies concurrently** (TCP connect, timeout 2 seconds)
4. Return **first proxy that successfully connects**
5. If none alive after 100 candidates → fallback to direct connection (no proxy)

```
get_random_proxy(proxy_mode)
    │
    ├─ proxy_mode='none' → return '' (direct, no proxy)
    │
    ├─ proxy_mode='auto' (default)
    │   ├─ No proxy in DB → return ''
    │   ├─ use_proxy=False in Settings → return ''
    │   └─ Test batch 20, get first alive
    │       └─ None alive → return '' (fallback)
    │
    └─ Return: 'http://IP:PORT'
```

### Per-Scan Proxy Options

When starting a scan, users can select proxy mode in **"Proxy Setup"** wizard:

| Option | Description | When to Use |
|--------|-----------|-----------------|
| **Use Proxy (auto)** | Use proxy if available, fallback to direct if not | Public targets / internet |
| **No Proxy (direct)** | Always direct connection, never use proxy | Local LAN / intranet targets |

> **Warning for LAN proxy mode:** Free public proxies add 100–500ms latency per request, making LAN scanning very slow. Use **No Proxy** mode for intranet targets.

### Manual Refresh Trigger

```bash
# Trigger proxy fetch now (without waiting 7 days)
docker exec parakang-celery-1 python -c \
  "from paraKang.tasks import fetch_free_proxies; r=fetch_free_proxies(); print(r)"

# Check schedule in DB
docker exec parakang-web-1 python manage.py shell -c "
from django_celery_beat.models import PeriodicTask
t = PeriodicTask.objects.get(name='Weekly proxy refresh & prune')
print('Interval:', t.interval, '| Enabled:', t.enabled, '| Last run:', t.last_run_at)
"

# Verify active proxy during scan
docker logs parakang-celery-1 --since=15m 2>&1 | grep -i "Using proxy\|no working proxy"
```

---

## Nuclei & DAST Templates
### Enabling DAST

DAST (Dynamic Application Security Testing) nuclei uses special templates from `/root/nuclei-templates/dast/`. Enable via YAML engine:

```yaml
vulnerability_scan:
  run_nuclei: true
  nuclei:
    run_dast: true               # enable DAST templates
    severities: [unknown, info, low, medium, high, critical]
    exclude_tags: [webauthn, passkey]   # tags to skip (common false positives)
```

When `run_dast: true`, three directories are added to nuclei command:

```
-t /root/nuclei-templates/dast/ai
-t /root/nuclei-templates/dast/cves
-t /root/nuclei-templates/dast/vulnerabilities
```

> nuclei recurses into each directory automatically, so all subdirectories (including yearly CVE folders: 2018, 2020, 2021, 2022, 2024) are scanned.

**Example generated nuclei command:**
```
nuclei -j -irr -l urls_unfurled.txt -c 50 -proxy http://1.2.3.4:8080
  -retries 1 -rl 150 -timeout 5 -etags webauthn,passkey -silent
  -t /root/nuclei-templates
  -t /root/nuclei-templates/dast/ai
  -t /root/nuclei-templates/dast/cves
  -t /root/nuclei-templates/dast/vulnerabilities
  -severity critical
```

**Verify DAST is active:**
```bash
# Check logs during scan
docker logs parakang-celery-1 --since=15m 2>&1 | grep -i "dast"
# Expected output:
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/ai (N files)
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/cves (N files)
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/vulnerabilities (N files)

# Verify actual nuclei command after scan
docker exec parakang-web-1 grep -a "^nuclei " \
  /usr/src/scan_results/*/commands.txt 2>/dev/null | grep dast | head -3
```

### Update Nuclei Templates

```bash
# Update nuclei templates (inside container)
docker exec parakang-celery-1 nuclei -update-templates

# Verify DAST directories exist
docker exec parakang-celery-1 ls /root/nuclei-templates/dast/
# Expected output: ai  cves  vulnerabilities

# Count total DAST templates
docker exec parakang-celery-1 find /root/nuclei-templates/dast/ -name "*.yaml" | wc -l
```

### Reducing False Positives

There are two ways to reduce false positives in nuclei.

#### 1. Via `exclude_tags` in YAML Engine (recommended)

Tags excluded from scanning:

```yaml
vulnerability_scan:
  nuclei:
    exclude_tags: [webauthn, passkey, dos, fuzz, intrusive]
```

Tags commonly producing excessive false positives:

| Tag | Reason |
|-----|--------|
| `webauthn` | Modern authentication templates, often false positive |
| `passkey` | Same as above |
| `dos` | Denial of Service — dangerous, rarely accurate |
| `fuzz` | Aggressive fuzzing, high noise |
| `intrusive` | Templates that modify server state |

#### 2. Via `exclude_templates` in YAML Engine

To exclude specific templates by path or ID:

```yaml
vulnerability_scan:
  nuclei:
    exclude_templates:
      - /root/nuclei-templates/miscellaneous/old-copyright.yaml
      - /root/nuclei-templates/technologies/tech-detect.yaml
```

#### 3. Manually Delete Vulnerability from UI

On **Scan Findings → Vulnerabilities** page, click delete button on false positive findings. Findings are only removed from that scan's database and don't affect future scans.

#### 4. View Stored Vulnerabilities

```bash
# View directly from database
docker exec parakang-db-1 psql -U parakang parakang -c \
  "SELECT name, severity, http_url FROM startScan_vulnerability \
   ORDER BY id DESC LIMIT 20;"
```

### Custom Nuclei Templates

To use your own nuclei templates:

1. Copy template into container:
   ```bash
   docker cp my-template.yaml parakang-celery-1:/root/nuclei-templates/custom/
   ```

2. Reference in YAML engine:
   ```yaml
   vulnerability_scan:
     nuclei:
       custom_templates:
         - custom/my-template   # without .yaml
   ```

---

## REST API Reference

ParaKang provides a comprehensive REST API for integration with external tools and automation. All endpoints require authentication via Django session or API token.

### Authentication

```bash
# Session-based (login via web):
curl -b cookies.txt -c cookies.txt http://localhost:8000/api/

# Token-based (recommended for scripts):
curl -H "Authorization: Bearer YOUR_API_TOKEN" http://localhost:8000/api/
```

Get API token at: Dashboard → Settings → API Token

### Main Endpoints

| Category | Endpoint | Method | Description |
|----------|----------|--------|-----------|
| **Targets** | `/api/queryTargets/` | GET | List all targets |
| **Targets** | `/api/add/target/` | POST | Create new target |
| **Subdomains** | `/api/listSubdomains/?domain_id=X` | GET | List subdomains |
| **Vulnerabilities** | `/api/listVulnerability/?scan_id=X` | GET | List vulnerability findings |
| **Endpoints** | `/api/listEndpoints/?domain_id=X` | GET | List HTTP endpoints |
| **Scans** | `/api/listScanHistory/?domain_id=X` | GET | List scan history |
| **HUMINT** | `/api/queryHumintEmployees/?scan_id=X` | GET | Employee enumeration |
| **SIGINT** | `/api/querySigintAsn/?scan_id=X` | GET | ASN/CIDR enumeration |
| **SIGINT** | `/api/querySigintEmailSecurity/?scan_id=X` | GET | Email security audit |
| **SIGINT** | `/api/querySigintCertificates/?scan_id=X` | GET | TLS certificate analysis |
| **Proxy** | `/api/tool/ollama/` | GET/POST | Manage Ollama models |
| **GPT** | `/api/tools/gpt_vulnerability_report/?id=X` | GET | LLM vulnerability description |

### Usage Examples

**Fetch all findings from scan:**
```bash
SCAN_ID=123
TOKEN="your_api_token"

curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/listVulnerability/?scan_id=$SCAN_ID" \
  | jq '.[] | {name, severity, cvss_score, http_url}'
```

**Create scan via API:**
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_id": 5,
    "engine_id": 1,
    "scan_mode": "active"
  }' \
  http://localhost:8000/api/add/target/
```

**Full API Documentation:**
```bash
# Access Swagger/OpenAPI docs
open http://localhost:8000/api/schema/
```

---

## Full Installation

### Prerequisites

- Docker and Docker Compose
- Operating System: Ubuntu 20.04+ / Debian / Kali Linux
- Minimum RAM: 4 GB (recommended 8 GB+)

### Installation Steps

```bash
# 1. Clone repository
git clone <url-repo-ini> paraKang-Custom && cd paraKang-Custom

# 2. Configure environment
cp .env.example .env
nano .env
# Minimum change: POSTGRES_PASSWORD

# 3. (Optional) Set first admin via .env
# DJANGO_SUPERUSER_USERNAME=admin
# DJANGO_SUPERUSER_EMAIL=admin@localhost
# DJANGO_SUPERUSER_PASSWORD=password_kuat

# 4. Run installer
sudo ./install.sh

# For non-interactive installation (automated):
sudo ./install.sh -n
```

After completion, access via `https://localhost` or `https://<IP-server>`.

### Celery Worker Configuration

Edit `.env` to adjust worker capacity:

| Variable | Default | Description |
|----------|---------|-----------|
| `MIN_CONCURRENCY` | 10 | Minimum active workers |
| `MAX_CONCURRENCY` | 30 | Maximum simultaneous workers |

Guide based on RAM:
- 4 GB RAM: `MAX_CONCURRENCY=10`
- 8 GB RAM: `MAX_CONCURRENCY=30`
- 16 GB RAM: `MAX_CONCURRENCY=50`

### Update

```bash
cd paraKang-Custom && sudo ./update.sh
```

---

## Troubleshooting

### Containers Cannot Start

**Symptom**: `docker compose up` error or container immediately exits

```bash
# Check logs
docker compose logs web --tail=50

# Common: database connection error
# Solution: Ensure POSTGRES_PASSWORD in .env changed from example
# Then rebuild: docker compose up -d --build
```

### Database Migration Error

**Symptom**: `django.db.utils.OperationalError: database does not exist`

```bash
# Restart database container
docker compose restart db

# Wait 10 seconds then try again
sleep 10
docker compose restart web

# If still error, reset database (WARNING: all data lost)
docker compose down -v
sudo ./install.sh -n
```

### Celery Worker Not Processing Tasks

**Symptom**: Scan stuck "In Progress" forever, no logs in Celery

```bash
# Check celery worker status
docker compose ps celery

# View logs
docker compose logs celery --tail=100

# Restart celery worker
docker compose restart celery

# Check Redis connection
docker exec parakang-redis-1 redis-cli ping
# Expected: PONG
```

### Ollama Model Pull Error

**Symptom**: "Model not found" or "Connection refused"

```bash
# Verify Ollama container running
docker compose ps ollama

# Check Ollama API endpoint
curl http://ollama:11434/api/tags

# Manual pull from container
docker exec parakang-ollama-1 ollama pull mistral

# View existing models
docker exec parakang-ollama-1 ollama list
```

### High Memory Usage / Out of Memory

**Symptom**: Container killed or system hang during scan

```bash
# Check memory usage
docker stats --no-stream

# Reduce concurrency in .env
MAX_CONCURRENCY=20  # from 30 to 20

# Reduce Celery memory limit
# Edit docker-compose.yml:
# celery:
#   mem_limit: 2g  # from 4g to 2g

docker compose up -d --build
```

### Proxy Test Failed

**Symptom**: "No working proxy found" or proxy connection timeout

```bash
# Force proxy refresh now (without waiting 7 days)
docker exec parakang-celery-1 python -c \
  "from paraKang.tasks import fetch_free_proxies; fetch_free_proxies()"

# Check proxy list in database
docker exec parakang-web-1 python manage.py shell
from dashboard.models import Proxy
print(f"Total proxies: {Proxy.objects.count()}")
exit()

# Manually set proxy
# Dashboard → Settings → Proxy → add IP:PORT
```

### Scan Timeout / Stuck

**Symptom**: Scan progress not updating, no error message

```bash
# Check Nginx proxy_timeout (default 900s)
docker exec parakang-proxy-1 cat /etc/nginx/nginx.conf | grep proxy_read_timeout

# If need to increase timeout (for large domain scans)
# Edit config/nginx/rengine.conf:
# proxy_read_timeout 1200;
# Then reload nginx:
docker exec parakang-proxy-1 nginx -s reload
```

### LLM Report Generation Error

**Symptom**: "Oops... Something went wrong!" when generating vulnerability report

```bash
# Check OpenAI API key
docker exec parakang-web-1 python manage.py shell
from paraKang.common_func import get_open_ai_key
print(f"OpenAI key configured: {bool(get_open_ai_key())}")
exit()

# Check Ollama model availability
docker exec parakang-web-1 python manage.py shell
from paraKang.common_func import get_available_ollama_models
models = get_available_ollama_models()
print(f"Available Ollama models: {[m['name'] for m in models]}")
exit()

# Increase proxy timeout (LLM requests can be long)
# Edit config/nginx/rengine.conf: proxy_read_timeout 900;
```

### Scan Results Not Showing

**Symptom**: Scan "Completed" but results empty

```bash
# Check scan task logs
docker compose logs celery | grep -i "scan_id=123"

# Verify database records
docker exec parakang-web-1 python manage.py shell
from startScan.models import ScanHistory
scan = ScanHistory.objects.get(id=123)
print(f"Subdomain count: {scan.subdomain_set.count()}")
print(f"Vulnerability count: {scan.vulnerability_set.count()}")
exit()

# Trigger subscan for specific domain
# Dashboard → Scan Results → Select Domain → SubScan
```

### Reset Admin Password

**If you forgot admin password:**

```bash
docker exec parakang-web-1 python manage.py changepassword admin

# Or create new superuser
docker exec parakang-web-1 python manage.py createsuperuser
```

### Rollback to Previous Version

```bash
# List commits
git log --oneline

# Checkout specific commit
git checkout abc1234

# Rebuild containers
docker compose build --no-cache
docker compose up -d
```

---

## Update History

All changes are tracked through git. The table below documents commit history since fork began.

| Commit | Date | Changes |
|--------|------|---------|
| `516186c` | 2026-03-11 | feat: weekly proxy refresh + prune dead entries (Celery Beat, every 7 days) |
| `dc190d7` | 2026-03-11 | fix: get_random_proxy batch-test 20 proxies concurrently — return first alive |
| `f1a1e94` | 2026-03-09 | feat(osint): add HUMINT and SIGINT, 7 new models, migration 0005, 7 new API endpoints |
| `e455064` | 2026-03-09 | fix: expand DAST CVE coverage, add 2024, use parent dast/cves/ directory |
| `c9fe1c6` | 2026-03-09 | fix: remove httpx duplicates; add 249 DAST nuclei templates; auto proxy-fetch for GooFuzz |
| `01584e6` | 2026-03-09 | fix: prevent scan stuck in "In Progress"; improve screenshot column visibility |
| `fd8e196` | 2026-03-08 | fix(dorking): detect GooFuzz IP block then skip; improve screenshot tab; add bing to theHarvester |
| `5261844` | 2026-03-08 | feat: add fetch_free_proxies task (scrape free proxies from 4 sources) + UI button |
| `67c7022` | 2026-03-08 | fix: prevent osint job.get() crash with allow_join_result(); improve invalid domain logging |
| `5e9752f` | 2026-03-08 | fix(osint): use free theHarvester sources only (not -b all) |
| `bc40df0` | 2026-03-08 | fix(deps): resolve tenacity conflict with langchain_core version |
| `ca742bd` | 2026-03-08 | fix(osint): improve OSINT tool integration; disable update notifications from upstream paraKang |
| `73ef07b` | 2026-03-07 | fix(osint): pin GooFuzz to v1.2.6; add jq to Dockerfile |
| `a55bf8c` | 2026-03-07 | fix: improve Ollama integration, report generation, and common utility functions |
| `b81c587` | 2026-03-02 | fix: improve Docker Compose configuration (network binding, healthcheck) |
| `b8601d5` | 2026-02-28 | fix: report generation 500 error (pin pydyf); fix OpenAI module import |
| `b97625c` | 2026-02-28 | feat: optimize Gunicorn; unify network binding to 0.0.0.0; close 7 HIGH security gaps |
| `dc1efef` | 2026-02-28 | fix(gunicorn): raise limit-request-line to 8190 for DataTables with long query |
| `49e8e06` | 2026-02-27 | feat: initial paraKang-Custom fork; 27 security findings from deep audit (2 CRITICAL, 7 HIGH, 10 MEDIUM, 8 LOW), all fixed; Nginx hardening |
---

## What's New

### AI-Powered Features

ParaKang now includes **12+ autonomous AI agents** that enhance reconnaissance and vulnerability assessment:

- **LLM-powered vulnerability descriptions** with OpenAI GPT or local Ollama
- **AI DAST templates** for advanced dynamic testing
- **Intelligent attack surface suggestions**
- **Automatic remediation recommendations**

### Key Improvements (v6.0)

- **150+ integrated security tools**
- **Advanced OSINT with HUMINT and SIGINT models**
- **Dynamic proxy system with automatic refresh**
- **Comprehensive DAST template coverage (249+ templates)**
- **Role-based access control (3 levels)**
- **REST API with 12+ endpoints**
- **Automatic false-positive reduction**
- **LLM-enhanced reporting**

---

License: [GPLv3](LICENSE)

---

<p align="center">Made with ❤️ by vulnLab f0r the Good Hum4n /:)\</p>
