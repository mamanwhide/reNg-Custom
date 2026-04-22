
# ParaKang

**Platform Otomasi Reconnaissance Terintegrasi untuk Penilaian Kerentanan Aplikasi Web**

ParaKang adalah platform berbasis kontainer Docker yang mengotomatisasi serangkaian lengkap pemindaian keamanan aplikasi web—dari enumerasi subdomain hingga assessment kerentanan dinamis, intelligence gathering komprehensif, dan analisis TLS.

## Daftar Isi

- [Ringkasan Eksekutif](#ringkasan-eksekutif)
- [Memulai Cepat](#memulai-cepat)
- [Konfigurasi Awal](#konfigurasi-awal)
- [Manajemen Pengguna dan Otentikasi](#manajemen-pengguna-dan-otentikasi)
- [Panduan Penggunaan](#panduan-penggunaan)
- [Arsitektur Sistem](#arsitektur-sistem)
- [Daftar Tools Terintegrasi](#daftar-tools-terintegrasi)
- [Sistem Proxy Dinamis](#sistem-proxy-dinamis)
- [Nuclei dan Template DAST](#nuclei-dan-template-dast)
- [REST API Reference](#rest-api-reference)
- [Instalasi Lengkap](#instalasi-lengkap)
- [Pemecahan Masalah](#pemecahan-masalah)
- [Riwayat Pembaruan](#riwayat-pembaruan)

---

## Ringkasan Eksekutif

ParaKang menyediakan orkestrasi terintegrasi dari 25+ alat reconnaissance dan vulnerability assessment berbasis Docker dengan koordinasi Celery untuk eksekusi paralel skala besar.

**Kemampuan Utama:**
- **Active Discovery**: Enumerasi subdomain dari 7 sumber berbeda, port scanning (naabu), HTTP probing (httpx), teknologi detection (Wappalyzer)
- **Intelligence Gathering**: HUMINT (GitHub org enumeration, LinkedIn employee discovery, job posting analysis), SIGINT (ASN/BGP enumeration, email security audit, TLS certificate analysis, passive intelligence via Shodan/Censys/InternetDB)
- **Vulnerability Assessment**: Template DAST nuclei (249+ template), reflected XSS detection (dalfox), CRLF injection (crlfuzz), S3 bucket misconfiguration, WAF detection (wafw00f)
- **Advanced Reporting**: LLM-enhanced vulnerability descriptions dengan dukungan OpenAI dan Ollama lokal, CVSS tracking, HackerOne integration
- **Advanced Features**: Dynamic proxy rotation dari 4 sumber publik, subscan targeting, intelligent de-duplication, role-based access control, webhook notifications (Slack/Discord/Telegram)

**Peningkatan Keamanan Edisi Custom:**
- 27 remediasi keamanan dari audit mendalam (2 CRITICAL, 7 HIGH, 10 MEDIUM, 8 LOW)
- Integrasi LLM yang diperbaiki untuk vulnerability reporting
- Template DAST komprehensif dengan kontrol false-positive granular
- Hardening proxy dengan deteksi IP blocking dan fallback otomatis
- Dynamic Ollama model selection untuk maksimum fleksibilitas

---

## Memulai Cepat

### Prasyarat Sistem

```
Sistem Operasi:  Ubuntu 20.04+ / Debian / Kali Linux
Docker:          20.10+ dengan Docker Compose 2.0+
RAM:             Minimum 4 GB (disarankan 8 GB+)
Disk:            Minimum 20 GB untuk scan results dan model
Koneksi:         Internet (untuk download tools dan models)
Akses Root:      Diperlukan untuk instalasi (sudo)
```

### Instalasi Cepat (3 Langkah)

**Langkah 1: Persiapan Repositori**
```bash
# Clone dan masuk direktori
git clone <repository-url> paraKang-Custom
cd paraKang-Custom

# Salin dan konfigurasi environment
cp .env.example .env

# Edit .env dengan text editor favorit
# Ubah PASSWORD: POSTGRES_PASSWORD, REDIS_PASSWORD
nano .env
```

**Langkah 2: Jalankan Installer**
```bash
# Mode interaktif (rekomendasi untuk first-time setup)
sudo ./install.sh

# Atau mode otomatis (non-interactive)
sudo ./install.sh -n
```

Proses ini akan:
- ✓ Memverifikasi Docker installation
- ✓ Build image container (web, celery, database, redis)
- ✓ Inisialisasi database PostgreSQL
- ✓ Jalankan migrasi Django
- ✓ Setup user admin pertama (via prompt atau .env)
- ✓ Siapkan Ollama container untuk LLM (opsional)

**Langkah 3: Akses Aplikasi**
```bash
# Verifikasi semua container running
docker compose ps

# Akses di browser
# HTTP (development):  http://localhost
# HTTPS (production):  https://localhost (dengan self-signed cert)
# API endpoint:        http://localhost:8000/api/
```

**Login Awal:**
- Username: `admin` (atau sesuai `DJANGO_SUPERUSER_USERNAME` di .env)
- Password: Sesuai `DJANGO_SUPERUSER_PASSWORD` di .env

---

## Konfigurasi Awal

### Variabel Environment Penting

Edit `.env` sebelum menjalankan `install.sh`:

| Variabel | Default | Keterangan |
|----------|---------|-----------|
| `POSTGRES_PASSWORD` | - | **WAJIB** ubah dari .env.example |
| `REDIS_PASSWORD` | - | **WAJIB** ubah dari .env.example |
| `DOMAIN_NAME` | `localhost` | Hostname untuk aplikasi (production: domain Anda) |
| `DEBUG` | `0` | Jangan ubah ke `1` di production |
| `DJANGO_SUPERUSER_USERNAME` | `admin` | Username admin pertama |
| `DJANGO_SUPERUSER_PASSWORD` | - | Password admin (auto-generate jika kosong) |
| `DJANGO_SUPERUSER_EMAIL` | `admin@localhost` | Email admin |
| `MIN_CONCURRENCY` | `10` | Minimum worker Celery aktif |
| `MAX_CONCURRENCY` | `30` | Maximum worker paralel (sesuaikan dengan RAM) |
| `GUNICORN_WORKERS` | `4` | Django worker processes |
| `GUNICORN_THREADS` | `2` | Thread per worker |

**Rekomendasi Concurrency Berdasarkan RAM:**
```
4 GB RAM:   MIN_CONCURRENCY=5,  MAX_CONCURRENCY=10
8 GB RAM:   MIN_CONCURRENCY=10, MAX_CONCURRENCY=30
16 GB RAM:  MIN_CONCURRENCY=20, MAX_CONCURRENCY=50
32 GB RAM:  MIN_CONCURRENCY=30, MAX_CONCURRENCY=100
```

### Integrasi API Eksternal (Opsional)

Setelah login ke Dashboard → Settings → API Vault, konfigurasi API key:

| Service | Konfigurasi | Kegunaan |
|---------|----------|----------|
| **OpenAI** | API Key | LLM untuk vulnerability description (rekomendasi: gpt-3.5-turbo atau gpt-4) |
| **Ollama** | Auto-detect (port 11434) | LLM offline local (alternativ OpenAI) |
| **Shodan** | API Key | Passive intelligence (open ports, CVE, services) |
| **Censys** | API ID + Secret | IP geolocation, certificate analysis |
| **Netlas** | API Key | Subdomain dan certificate enumeration |
| **HackerOne** | Username + API Key | Sync bug bounty programs |
| **Slack / Discord / Telegram** | Webhook URL | Notifikasi scan completion |

### Setup Proxy (Opsional)

```bash
# Manual: Dashboard → Settings → Proxy
# Setup: Masukkan IP:PORT proxy lokal jika ada

# Otomatis: Proxy publik gratis di-fetch setiap 7 hari
# Cek jadwal di Dashboard → Activity Logs
```

---

## Manajemen Pengguna dan Otentikasi

### Struktur Role dan Permissions

ParaKang memiliki 3 role dengan hirarki izin:

| Role | Akses | Keterangan |
|------|-------|-----------|
| **System Administrator** | Semua fitur | Full access: config sistem, semua scan, user management, API keys |
| **Penetration Tester** | Scan & Targets | Create/edit targets, run scans, subscan, view results (tidak bisa akses settings sistem) |
| **Auditor** | Read-only | Hanya view hasil scan dan generate report (tidak bisa create scan) |

### Membuat User Baru

**Metode 1: Via Django Admin (Recommended)**
```bash
# Akses Django admin shell
docker exec parakang-web-1 python manage.py shell

# Di Python shell:
from django.contrib.auth import get_user_model
User = get_user_model()

# Buat user baru
user = User.objects.create_user(
    username='john_pentester',
    email='john@company.com',
    password='SecurePassword123!',
    first_name='John',
    last_name='Doe'
)

# Assign role (menggunakan django-role-permissions)
from rolepermissions.roles import assign_role
assign_role(user, 'penetration_tester')

print(f"User created: {user.username} with role: penetration_tester")
exit()
```

**Metode 2: Via Django Command (Production)**
```bash
docker exec parakang-web-1 python manage.py createsuperuser \
  --username john_admin \
  --email john@company.com
  
# Ikuti prompt untuk password
# Lalu assign role via Django shell (Metode 1)
```

**Metode 3: Via Django Admin Web Interface**
```
1. Login ke https://localhost/admin/ dengan credentials admin
2. Navigate ke: Users
3. Click: Add User
4. Isi: username, email, password
5. Save
6. Edit kembali user yang baru dibuat
7. Di group section, assign role yang sesuai
8. Save
```

### Mengubah Password User

**User Mengubah Sendiri:**
```
1. Login ke aplikasi
2. Click profile icon (top-right)
3. Click "Change Password"
4. Masukkan password lama dan baru
5. Save
```

**Admin Mereset Password User:**
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

### Mengelola Role dan Permission

```bash
# List semua user dan role mereka
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

Setiap user dapat mengkonfigurasi preference di Dashboard → Settings:

| Setting | Default | Keterangan |
|---------|---------|-----------|
| **Bug Bounty Mode** | Off | Highlight hanya findings yang bug bounty-relevant |
| **Notification Preference** | On | Enable/disable notifikasi |
| **API Token** | Auto-gen | REST API authentication |

---

## Panduan Penggunaan

---

### Membuat dan Menjalankan Scan

**Langkah 1: Buat Project (Container Logis)**
```
Dashboard → Projects → New Project
  Project Name: "PT-Client-ABC"
  Description: "Penetration test for ABC Corporation"
  Create
```

**Langkah 2: Tambah Target Domain**
```
Dashboard → Targets (di bawah project) → Add Target
  Domain: example.com
  Organization: ABC Corp (optional)
  In Scope CIDR: 192.0.2.0/24 (untuk target private)
  Custom Headers: X-Custom-Header: value
  Save
```

**Langkah 3: Pilih Scan Engine dan Jalankan**
```
Target detail page → Initiate Scan
  Select Engine: "Full Scan" atau custom engine
  Proxy Mode: Auto (gunakan proxy) / Direct (tanpa proxy)
  Intensity: Normal / Aggressive (impact ke rate limiting)
  Start Scan
```

**Monitoring Scan Progress:**
- Real-time progress bar di Dashboard
- View logs: Activity Logs tab
- Cancel anytime jika perlu

**Langkah 4: Review Hasil**
```
Scan Results → Findings
  Filter by: Severity (Critical/High/Medium/Low)
  Filter by: Type (Subdomain/Endpoint/Vulnerability)
  Export: CSV / JSON / PDF Report
```

### Subscan (Re-scan Target Spesifik)

Untuk scan ulang domain atau subdomain tanpa full scan:

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

### Menggunakan Scan Engines Kustom

Buat engine configuration YAML untuk workflow spesifik:

**Dashboard → Scan Engines → Create Custom Engine**

```yaml
# Contoh: OSINT Only (no active scanning)
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

### Eksport dan Reporting

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

**API Integration untuk Custom Reporting:**
```bash
# Fetch semua vulnerability dari scan tertentu
curl -H "Authorization: Bearer $API_TOKEN" \
  "http://localhost:8000/api/listVulnerability/?scan_id=123"

# Response: JSON array dengan vulnerability details
```

---

## Arsitektur Sistem

```
Browser (HTTPS)
    |
    v
Nginx (reverse proxy, TLS termination)
    |
    v
Gunicorn / Django (web + REST API)
    |
    +---> PostgreSQL  (semua data recon disimpan di sini)
    |
    v
Celery Workers  <---  Redis (message broker + result backend)
    |
    +--- main_scan_queue        : orkestrasi scan utama
    +--- subscan_queue          : subscan per subdomain
    +--- osint_discovery_queue  : OSINT, HUMINT, SIGINT, theHarvester
    +--- dorking_queue          : Google/Bing dork via GooFuzz
    +--- theHarvester_queue     : email, subdomain, employee harvest
    +--- h8mail_queue           : credential breach check
    +--- vulnerability_scan_queue : nuclei, dalfox, crlfuzz
    +--- (dan antrean lainnya)
    |
    v
Scan Result Files
    /usr/src/app/scan_results/{domain}/{scan_id}/
```

Alur kerja scan:

1. Pengguna membuat target, memilih engine, klik "Initiate Scan"
2. `initiate_scan` (Celery task) membuat `ScanHistory`, lalu membangun Celery chord:
   - Grup paralel: subdomain discovery, OSINT, port scan
   - Setelah grup selesai: HTTP crawl, dir/file fuzz, fetch URL
   - Paralel lagi: vulnerability scan, screenshot, WAF detection
3. Setiap task menyimpan hasilnya langsung ke PostgreSQL
4. Antarmuka web mem-poll via REST API untuk memperbarui UI secara live

---

## Daftar Tools Terintegrasi

| Kategori | Tool | Keterangan |
|----------|------|-----------|
| Subdomain Discovery | subfinder, ctfr, sublist3r, tlsx, oneforall, netlas, chaos | Enumerasi subdomain dari berbagai sumber |
| HTTP Crawl | httpx | Probing HTTP/HTTPS ke semua subdomain, ambil status, header, title |
| Port Scan | naabu | Fast port scanner; opsional dilanjutkan nmap |
| Directory Fuzz | ffuf | Directory dan file fuzzing |
| Endpoint Discovery | gospider, hakrawler, waybackurls, katana, gau | Crawl dan arsip URL |
| Screenshot | gowitness | Screenshot setiap subdomain yang hidup |
| Vulnerability Scan | nuclei | Template CVE, DAST AI, DAST vulnerabilities (249 template custom) |
| XSS | dalfox | Reflected dan DOM XSS |
| CRLF | crlfuzz | CRLF injection |
| S3 Bucket | s3scanner | Misconfigured S3 detection |
| OSINT | theHarvester | Email, subdomain, employee dari Bing, CertSpotter, HunterIO, dll |
| OSINT | h8mail | Credential breach check |
| OSINT Dork | GooFuzz | Google/Bing dork (login pages, admin panels, config files, dll) |
| HUMINT | humint_github_recon | GitHub org recon: members, repos, email dari commit, deteksi secrets |
| HUMINT | humint_linkedin_recon | Bing dork site:linkedin.com/in/ untuk enumerasi karyawan |
| HUMINT | humint_job_postings | Job posting dork: ekstraksi tech stack (AWS, K8s, LDAP, dll) |
| SIGINT | sigint_asn_recon | ASN/BGP enumeration via BGPView.io + amass intel |
| SIGINT | sigint_email_security | Audit SPF, DKIM (20 selector), DMARC + penilaian risiko spoofing |
| SIGINT | sigint_passive_intel | Shodan/Censys/InternetDB: open ports, CVEs, services per IP |
| SIGINT | sigint_cert_analysis | TLS handshake langsung + CT log (crt.sh), deteksi cert expired/self-signed/SHA1 |
| LLM | Ollama / OpenAI GPT | Deskripsi kerentanan, impact, remediation, attack surface suggestion |
| WAF | wafw00f | Web Application Firewall detection |
| WHOIS | built-in | Domain registration info |

---

## Sistem Proxy Dinamis

paraKang-Custom menggunakan proxy untuk melindungi IP asli selama scanning (terutama subdomain discovery, nuclei, fetch URL, dan dorking Google). Sistem proxy bersifat otomatis — tidak perlu konfigurasi manual jika menggunakan proxy gratis.

### Sumber Proxy

Proxy diambil secara otomatis dari 4 sumber publik:

| # | Sumber | URL | Metode |
|---|--------|-----|--------|
| 1 | **proxifly** | `cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/.../data.json` | JSON CDN — paling reliable |
| 2 | **proxyscrape** | `api.proxyscrape.com/v3/free-proxy-list/get?protocol=http...` | Plain-text REST API |
| 3 | **free-proxy-list.net** | `https://free-proxy-list.net/` | HTML table scraping |
| 4 | **proxylistfree.com** | `https://www.proxylistfree.com/` | HTML table scraping |

Semua proxy tersimpan di `Settings → Proxy` (field `proxies`) dalam format `IP:PORT` satu entri per baris.

### Alur Kerja Otomatis (Celery Beat)

```
Worker startup (parakang-celery-1)
    │
    ▼
worker_ready signal (celery.py)
    │
    ▼
Daftarkan PeriodicTask ke DB:
  name: "Weekly proxy refresh & prune"
  task: fetch_free_proxies
  jadwal: setiap 7 hari
    │
    ▼
parakang-celery-beat-1 (DatabaseScheduler)
  polling DB tiap ~5 detik
    │
    ▼  [setiap 7 hari]
fetch_free_proxies()
    ├─ Scrape 4 sumber → kumpulkan IP:PORT baru
    ├─ Test semua proxy EXISTING di DB
    │   └─ 50 thread, TCP connect timeout 2 detik
    │       ├─ Hidup  → dipertahankan
    │       └─ Mati   → dihapus (pruned)
    ├─ Merge: proxy lama yang masih hidup + proxy baru
    └─ Simpan ke DB
```

**Contoh log refresh:**
```
fetch_free_proxies: proxifly gave 523 proxies
fetch_free_proxies: proxyscrape added 312
fetch_free_proxies: free-proxy-list added 89
fetch_free_proxies: testing 2039 existing proxies for liveness...
fetch_free_proxies: pruned 1847 dead proxies, 192 still alive
fetch_free_proxies: +968 new, -1847 dead removed, 1160 total in DB
```

### Pemilihan Proxy saat Scan (get_random_proxy)

Setiap kali tool (nuclei, httpx, naabu, dll) membutuhkan proxy, sistem:

1. Mengambil daftar proxy dari DB
2. Mengacak urutan (`random.shuffle`)
3. Menguji **batch 20 proxy secara concurrent** (TCP connect, timeout 2 detik)
4. Mengembalikan **proxy pertama yang berhasil konek**
5. Jika tidak ada yang hidup setelah 100 kandidat → fallback ke koneksi langsung (tanpa proxy)

```
get_random_proxy(proxy_mode)
    │
    ├─ proxy_mode='none' → return '' (langsung, tidak pakai proxy)
    │
    ├─ proxy_mode='auto' (default)
    │   ├─ Tidak ada proxy di DB → return ''
    │   ├─ use_proxy=False di Settings → return ''
    │   └─ Test batch 20, ambil yang pertama hidup
    │       └─ Tidak ada yang hidup → return '' (fallback)
    │
    └─ Return: 'http://IP:PORT'
```

### Opsi Per-Scan (Proxy Setup UI)

Saat memulai scan, pengguna dapat memilih mode proxy di wizard **"Proxy Setup"**:

| Opsi | Keterangan | Kapan Digunakan |
|------|-----------|-----------------|
| **Use Proxy (auto)** | Gunakan proxy jika tersedia, fallback langsung jika tidak ada | Target publik / internet |
| **No Proxy (direct)** | Selalu koneksi langsung, tidak pernah pakai proxy | Target LAN / intranet lokal |

> **Peringatan mode proxy di jaringan LAN:** Proxy publik gratis menambahkan latensi 100–500ms per request, membuat scanning LAN sangat lambat. Gunakan mode **No Proxy** untuk target intranet.

### Trigger Refresh Manual

```bash
# Trigger fetch proxy sekarang (tanpa menunggu 7 hari)
docker exec parakang-celery-1 python -c \
  "from paraKang.tasks import fetch_free_proxies; r=fetch_free_proxies(); print(r)"

# Cek jadwal di DB
docker exec parakang-web-1 python manage.py shell -c "
from django_celery_beat.models import PeriodicTask
t = PeriodicTask.objects.get(name='Weekly proxy refresh & prune')
print('Interval:', t.interval, '| Enabled:', t.enabled, '| Last run:', t.last_run_at)
"

# Verifikasi proxy aktif saat scan berjalan
docker logs parakang-celery-1 --since=15m 2>&1 | grep -i "Using proxy\|no working proxy"
```

---

## Nuclei dan Template DAST

### Mengaktifkan DAST

DAST (Dynamic Application Security Testing) nuclei menggunakan template khusus dari direktori `/root/nuclei-templates/dast/`. Aktifkan via YAML engine:

```yaml
vulnerability_scan:
  run_nuclei: true
  nuclei:
    run_dast: true               # aktifkan DAST templates
    severities: [unknown, info, low, medium, high, critical]
    exclude_tags: [webauthn, passkey]   # tag yang di-skip (false positive umum)
```

Saat `run_dast: true`, tiga direktori ditambahkan ke perintah nuclei:

```
-t /root/nuclei-templates/dast/ai
-t /root/nuclei-templates/dast/cves
-t /root/nuclei-templates/dast/vulnerabilities
```

> nuclei merekursi ke dalam setiap direktori secara otomatis, sehingga semua subdirektori (termasuk CVE per tahun: 2018, 2020, 2021, 2022, 2024) ikut di-scan.

**Contoh command nuclei yang dihasilkan:**
```
nuclei -j -irr -l urls_unfurled.txt -c 50 -proxy http://1.2.3.4:8080
  -retries 1 -rl 150 -timeout 5 -etags webauthn,passkey -silent
  -t /root/nuclei-templates
  -t /root/nuclei-templates/dast/ai
  -t /root/nuclei-templates/dast/cves
  -t /root/nuclei-templates/dast/vulnerabilities
  -severity critical
```

**Verifikasi DAST aktif:**
```bash
# Cek log saat scan berjalan
docker logs parakang-celery-1 --since=15m 2>&1 | grep -i "dast"
# Output yang diharapkan:
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/ai (N files)
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/cves (N files)
# nuclei_scan: added DAST templates dir /root/nuclei-templates/dast/vulnerabilities (N files)

# Verifikasi command nuclei aktual pasca scan
docker exec parakang-web-1 grep -a "^nuclei " \
  /usr/src/scan_results/*/commands.txt 2>/dev/null | grep dast | head -3
```

### Update Template Nuclei

```bash
# Update template nuclei (di dalam container)
docker exec parakang-celery-1 nuclei -update-templates

# Verifikasi direktori DAST ada
docker exec parakang-celery-1 ls /root/nuclei-templates/dast/
# Output yang diharapkan: ai  cves  vulnerabilities

# Hitung total template DAST
docker exec parakang-celery-1 find /root/nuclei-templates/dast/ -name "*.yaml" | wc -l
```

### Menghapus False Positive

Ada dua cara untuk mengurangi false positive di nuclei.

#### 1. Via `exclude_tags` di YAML Engine (direkomendasikan)

Tags yang dikeluarkan dari scanning:

```yaml
vulnerability_scan:
  nuclei:
    exclude_tags: [webauthn, passkey, dos, fuzz, intrusive]
```

Tags yang umum menghasilkan false positive berlebihan:

| Tag | Alasan |
|-----|--------|
| `webauthn` | Template autentikasi modern, sering false positive |
| `passkey` | Idem |
| `dos` | Denial of Service — berbahaya, jarang akurat |
| `fuzz` | Fuzzing agresif, noise tinggi |
| `intrusive` | Template yang mengubah state server |

#### 2. Via `exclude_templates` di YAML Engine

Untuk mengecualikan template tertentu berdasarkan path atau ID:

```yaml
vulnerability_scan:
  nuclei:
    exclude_templates:
      - /root/nuclei-templates/miscellaneous/old-copyright.yaml
      - /root/nuclei-templates/technologies/tech-detect.yaml
```

#### 3. Hapus Vulnerability Manual dari UI

Di halaman **Scan Findings → Vulnerabilities**, klik tombol hapus pada temuan yang merupakan false positive. Temuan hanya dihapus dari DB scan tersebut dan tidak memengaruhi scan berikutnya.

#### 4. Lihat Vulnerability yang Sudah Tersimpan

```bash
# Lihat dari database langsung
docker exec parakang-db-1 psql -U parakang parakang -c \
  "SELECT name, severity, http_url FROM startScan_vulnerability \
   ORDER BY id DESC LIMIT 20;"
```

### Custom Nuclei Templates

Untuk menggunakan template nuclei sendiri:

1. Salin template ke dalam container:
   ```bash
   docker cp my-template.yaml parakang-celery-1:/root/nuclei-templates/custom/
   ```

2. Referensikan di YAML engine:
   ```yaml
   vulnerability_scan:
     nuclei:
       custom_templates:
         - custom/my-template   # tanpa .yaml
   ```

---

## REST API Reference

ParaKang menyediakan REST API lengkap untuk integrasi dengan tools eksternal dan automation. Semua endpoint memerlukan authentication via session Django atau API token.

### Authentication

```bash
# Session-based (login via web):
curl -b cookies.txt -c cookies.txt http://localhost:8000/api/

# Token-based (recommended untuk scripts):
curl -H "Authorization: Bearer YOUR_API_TOKEN" http://localhost:8000/api/
```

Dapatkan API token di: Dashboard → Settings → API Token

### Endpoint Utama

| Kategori | Endpoint | Method | Deskripsi |
|----------|----------|--------|-----------|
| **Targets** | `/api/queryTargets/` | GET | List semua target |
| **Targets** | `/api/add/target/` | POST | Buat target baru |
| **Subdomains** | `/api/listSubdomains/?domain_id=X` | GET | List subdomain |
| **Vulnerabilities** | `/api/listVulnerability/?scan_id=X` | GET | List vulnerability findings |
| **Endpoints** | `/api/listEndpoints/?domain_id=X` | GET | List HTTP endpoints |
| **Scans** | `/api/listScanHistory/?domain_id=X` | GET | List scan history |
| **HUMINT** | `/api/queryHumintEmployees/?scan_id=X` | GET | Karyawan enumeration |
| **SIGINT** | `/api/querySigintAsn/?scan_id=X` | GET | ASN/CIDR enumeration |
| **SIGINT** | `/api/querySigintEmailSecurity/?scan_id=X` | GET | Email security audit |
| **SIGINT** | `/api/querySigintCertificates/?scan_id=X` | GET | TLS certificate analysis |
| **Proxy** | `/api/tool/ollama/` | GET/POST | Manage Ollama models |
| **GPT** | `/api/tools/gpt_vulnerability_report/?id=X` | GET | LLM vulnerability description |

### Contoh Penggunaan

**Fetch semua findings dari scan:**
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

**Dokumentasi lengkap API:**
```bash
# Access Swagger/OpenAPI docs
open http://localhost:8000/api/schema/
```

---

## Instalasi Lengkap

### Prasyarat

- Docker dan Docker Compose
- Sistem operasi: Ubuntu 20.04+ / Debian / Kali Linux
- RAM minimum: 4 GB (disarankan 8 GB+)

### Langkah Instalasi

```bash
# 1. Clone repository
git clone <url-repo-ini> paraKang-Custom && cd paraKang-Custom

# 2. Konfigurasi environment
cp .env.example .env
nano .env
# Minimal ubah: POSTGRES_PASSWORD

# 3. (Opsional) Set admin pertama via .env
# DJANGO_SUPERUSER_USERNAME=admin
# DJANGO_SUPERUSER_EMAIL=admin@localhost
# DJANGO_SUPERUSER_PASSWORD=password_kuat

# 4. Jalankan installer
sudo ./install.sh

# Untuk instalasi tanpa interaksi (otomatis):
sudo ./install.sh -n
```

Setelah selesai, akses via `https://localhost` atau `https://<IP-server>`.

### Konfigurasi Worker Celery

Edit `.env` untuk menyesuaikan kapasitas worker:

| Variabel | Default | Keterangan |
|----------|---------|-----------|
| `MIN_CONCURRENCY` | 10 | Minimum worker aktif |
| `MAX_CONCURRENCY` | 30 | Maximum worker bersamaan |

Panduan berdasarkan RAM:
- 4 GB RAM: `MAX_CONCURRENCY=10`
- 8 GB RAM: `MAX_CONCURRENCY=30`
- 16 GB RAM: `MAX_CONCURRENCY=50`

### Pembaruan

```bash
cd paraKang-Custom && sudo ./update.sh
```

---

## Pemecahan Masalah

### Container Tidak Bisa Start

**Gejala**: `docker compose up` error atau container immediately exits

```bash
# Check logs
docker compose logs web --tail=50

# Umum: database connection error
# Solusi: Pastikan POSTGRES_PASSWORD di .env sudah diubah dari contoh
# Lalu rebuild: docker compose up -d --build
```

### Database Migration Error

**Gejala**: `django.db.utils.OperationalError: database does not exist`

```bash
# Restart database container
docker compose restart db

# Tunggu 10 detik lalu coba lagi
sleep 10
docker compose restart web

# Jika tetap error, reset database (WARNING: semua data hilang)
docker compose down -v
sudo ./install.sh -n
```

### Celery Worker Tidak Memproses Task

**Gejala**: Scan "In Progress" selamanya, logs tidak ada di Celery

```bash
# Check celery worker status
docker compose ps celery

# Lihat logs
docker compose logs celery --tail=100

# Restart celery worker
docker compose restart celery

# Check Redis connection
docker exec parakang-redis-1 redis-cli ping
# Expected: PONG
```

### Ollama Model Pull Error

**Gejala**: "Model not found" atau "Connection refused"

```bash
# Verifikasi Ollama container running
docker compose ps ollama

# Check Ollama API endpoint
curl http://ollama:11434/api/tags

# Manual pull dari container
docker exec parakang-ollama-1 ollama pull mistral

# Lihat models yang sudah ada
docker exec parakang-ollama-1 ollama list
```

### High Memory Usage / Out of Memory

**Gejala**: Container killed atau system hang saat scan berjalan

```bash
# Check memory usage
docker stats --no-stream

# Kurangi concurrency di .env
MAX_CONCURRENCY=20  # dari 30 menjadi 20

# Reduce Celery memory limit
# Edit docker-compose.yml:
# celery:
#   mem_limit: 2g  # dari 4g menjadi 2g

docker compose up -d --build
```

### Proxy Test Gagal

**Gejala**: "No working proxy found" atau proxy connection timeout

```bash
# Force proxy refresh sekarang (tidak tunggu 7 hari)
docker exec parakang-celery-1 python -c \
  "from paraKang.tasks import fetch_free_proxies; fetch_free_proxies()"

# Check proxy list di database
docker exec parakang-web-1 python manage.py shell
from dashboard.models import Proxy
print(f"Total proxies: {Proxy.objects.count()}")
exit()

# Manual set proxy
# Dashboard → Settings → Proxy → tambahkan IP:PORT
```

### Scan Timeout / Stuck

**Gejala**: Scan progress tidak update, tidak ada error

```bash
# Check Nginx proxy_timeout (default 900s)
docker exec parakang-proxy-1 cat /etc/nginx/nginx.conf | grep proxy_read_timeout

# Jika perlu increase timeout (untuk scan domain besar)
# Edit config/nginx/rengine.conf:
# proxy_read_timeout 1200;
# Lalu reload nginx:
docker exec parakang-proxy-1 nginx -s reload
```

### LLM Report Generation Error

**Gejala**: "Oops... Something went wrong!" saat generate vulnerability report

```bash
# Check OpenAI API key
docker exec parakang-web-1 python manage.py shell
from paraKang.common_func import get_open_ai_key
print(f"OpenAI key configured: {bool(get_open_ai_key())}")
exit()

# Cek Ollama model availability
docker exec parakang-web-1 python manage.py shell
from paraKang.common_func import get_available_ollama_models
models = get_available_ollama_models()
print(f"Available Ollama models: {[m['name'] for m in models]}")
exit()

# Increase proxy timeout (LLM requests bisa lama)
# Edit config/nginx/rengine.conf: proxy_read_timeout 900;
```

### Scan Results Tidak Muncul

**Gejala**: Scan "Completed" tapi hasil kosong

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

# Trigger subscan untuk domain tertentu
# Dashboard → Scan Results → Select Domain → SubScan
```

### Reset Admin Password

**Jika lupa password admin:**

```bash
docker exec parakang-web-1 python manage.py changepassword admin

# Atau create superuser baru
docker exec parakang-web-1 python manage.py createsuperuser
```

### Rollback ke Versi Sebelumnya

```bash
# List commits
git log --oneline

# Checkout ke commit tertentu
git checkout abc1234

# Rebuild containers
docker compose build --no-cache
docker compose up -d
```

---

## Riwayat Pembaruan

Semua perubahan dilacak melalui git. Tabel di bawah mencatat riwayat commit sejak fork dimulai.

| Commit | Tanggal | Perubahan |
|--------|---------|-----------|
| `516186c` | 2026-03-11 | feat: weekly proxy refresh + prune dead entries (Celery Beat, setiap 7 hari) |
| `dc190d7` | 2026-03-11 | fix: get_random_proxy batch-test 20 proxy concurrent — kembalikan yang pertama hidup |
| `f1a1e94` | 2026-03-09 | feat(osint): tambah HUMINT dan SIGINT, 7 model baru, migrasi 0005, 7 API endpoint baru |
| `e455064` | 2026-03-09 | fix: perbaiki cakupan DAST CVE, tambah 2024, gunakan dir induk dast/cves/ |
| `c9fe1c6` | 2026-03-09 | fix: hapus duplikat httpx; tambah 249 template DAST nuclei; proxy auto-fetch untuk GooFuzz |
| `01584e6` | 2026-03-09 | fix: cegah scan stuck di "In Progress"; perbaiki visibilitas kolom screenshot |
| `fd8e196` | 2026-03-08 | fix(dorking): deteksi blokir IP GooFuzz lalu skip; perbaiki tab screenshot; tambah bing ke theHarvester |
| `5261844` | 2026-03-08 | feat: tambah task fetch_free_proxies (scrape proxy gratis dari 4 sumber) + tombol UI |
| `67c7022` | 2026-03-08 | fix: crash osint job.get() dengan allow_join_result(); perbaiki log domain tidak valid |
| `5e9752f` | 2026-03-08 | fix(osint): gunakan sumber theHarvester gratis saja (bukan -b all) |
| `bc40df0` | 2026-03-08 | fix(deps): perbaiki konflik versi tenacity dengan langchain_core |
| `ca742bd` | 2026-03-08 | fix(osint): perbaikan integrasi tool OSINT; nonaktifkan notifikasi update dari upstream paraKang |
| `73ef07b` | 2026-03-07 | fix(osint): pin GooFuzz ke v1.2.6; tambah jq ke Dockerfile |
| `a55bf8c` | 2026-03-07 | fix: perbaikan integrasi Ollama, report generation, dan beberapa fungsi umum |
| `b81c587` | 2026-03-02 | fix: perbaikan konfigurasi Docker Compose (network binding, healthcheck) |
| `b8601d5` | 2026-02-28 | fix: report generation 500 error (pin pydyf); perbaiki OpenAI module import |
| `b97625c` | 2026-02-28 | feat: optimalkan Gunicorn; satukan network binding ke 0.0.0.0; tutup 7 celah keamanan HIGH |
| `dc1efef` | 2026-02-28 | fix(gunicorn): naikkan limit-request-line ke 8190 untuk DataTables dengan query panjang |
| `49e8e06` | 2026-02-27 | feat: fork awal paraKang-Custom; audit keamanan 27 temuan (2 CRITICAL, 7 HIGH, 10 MEDIUM, 8 LOW), semua diperbaiki; hardening Nginx |

### Ringkasan Keamanan (Audit Awal)

| Tingkat | Jumlah | Status |
|---------|--------|--------|
| CRITICAL | 2 | Semua diperbaiki |
| HIGH | 7 | Semua diperbaiki |
| MEDIUM | 10 | Semua diperbaiki |
| LOW | 8 | Semua diperbaiki |
| **Total** | **27** | **Semua diperbaiki** |

Detail lengkap tersedia di [PARAKANG_DEEP_AUDIT_V2.md](PARAKANG_DEEP_AUDIT_V2.md).

---

Lisensi: [GPLv3](LICENSE)
