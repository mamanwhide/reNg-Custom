# reNgine-Custom

Fork privat dari [reNgine v2.2.0](https://github.com/yogeshojha/rengine) dengan perbaikan keamanan, penyempurnaan fungsional, dan tambahan kemampuan OSINT tingkat lanjut (HUMINT dan SIGINT).

---

## Daftar Isi

- [TL;DR](#tldr)
- [Arsitektur dan Cara Kerja](#arsitektur-dan-cara-kerja)
- [Daftar Tools](#daftar-tools)
- [Cara Menggunakan](#cara-menggunakan)
- [Instalasi](#instalasi)
- [Riwayat Pembaruan](#riwayat-pembaruan)

---

## TL;DR

reNgine-Custom adalah platform otomasi reconnaissance web aplikasi berbasis Docker. Pengguna mendefinisikan target domain, memilih scan engine (sekumpulan konfigurasi YAML), lalu sistem menjalankan seluruh tahapan recon secara otomatis mulai dari enumerasi subdomain hingga pemindaian kerentanan, OSINT, dan analisis sertifikat TLS, semuanya disimpan ke database PostgreSQL dan dapat difilter via antarmuka web.

Fork ini menambahkan:
- 27 perbaikan keamanan (dari audit mendalam terhadap 20 file sumber)
- Perbaikan integrasi Ollama LLM untuk laporan kerentanan
- OSINT mendalam: HUMINT (GitHub org recon, LinkedIn dork, job posting intel) dan SIGINT (ASN/BGP, SPF/DKIM/DMARC, passive intel via Shodan, analisis sertifikat TLS)
- Perbaikan dorking (deteksi blokir GooFuzz, fallback Bing, proxy otomatis)
- Template DAST nuclei (249 template: AI, CVE, vulnerabilities) dengan eksklusi false-positive

---

## Arsitektur dan Cara Kerja

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

## Daftar Tools

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

## Cara Menggunakan

### Menjalankan Scan

1. Buka antarmuka web di `https://localhost` (atau IP server)
2. Buat project baru (menu Projects)
3. Tambahkan target domain (menu Targets)
4. Pilih scan engine dari daftar yang tersedia:
   - **Full Scan**: semua modul aktif termasuk HUMINT, SIGINT, DAST
   - **OSINT**: hanya OSINT, HUMINT, SIGINT, dorking
   - **Subdomain Scan**: hanya enumerasi subdomain
   - **Vulnerability Scan**: subdomain + port scan + nuclei
   - **Port Scan**: hanya port scan
   - **reNgine Recommended**: set default yang seimbang
5. Klik "Initiate Scan"

### Konfigurasi Scan Engine (YAML)

Setiap engine dikonfigurasi via YAML. Contoh untuk mengaktifkan HUMINT dan SIGINT pada OSINT engine:

```yaml
osint:
  discover: [emails, metainfo, employees]
  dorks: [login_pages, admin_panels, config_files, git_exposed]
  humint:
    github_org: true
    linkedin: true
    job_postings: true
  sigint:
    asn_recon: true
    email_security: true
    passive_intel: false   # perlu SHODAN_API_KEY di settings
    cert_analysis: true
  documents_limit: 50
```

### Subscan

Untuk scan ulang domain atau subdomain tertentu tanpa menjalankan full scan:
- Di halaman hasil scan, klik subdomain yang ingin di-subscan
- Pilih jenis subscan (port scan, vulnerability scan, screenshot, dll)

### Notifikasi

Notifikasi aktif untuk:
- Subdomain baru ditemukan
- Kerentanan baru ditemukan
- Commit baru di repository ini (via endpoint `/api/rengine/update/`)

Notifikasi dari GitHub upstream reNgine (yogeshojha/rengine) telah dinonaktifkan.

### Melihat Hasil HUMINT / SIGINT

Hasil HUMINT dan SIGINT tersedia via REST API:

| Endpoint | Isi |
|----------|-----|
| `/api/queryHumintEmployees/?scan_id=X` | Profil karyawan dari GitHub dan LinkedIn |
| `/api/queryHumintGithub/?scan_id=X` | Hasil GitHub org recon |
| `/api/queryHumintJobPostings/?scan_id=X` | Job posting dan tech stack |
| `/api/querySigintAsn/?scan_id=X` | Daftar ASN dan CIDR ranges |
| `/api/querySigintEmailSecurity/?scan_id=X` | SPF, DKIM, DMARC, risiko spoofing |
| `/api/querySigintIntelligence/?scan_id=X` | IP, port terbuka, CVE dari Shodan |
| `/api/querySigintCertificates/?scan_id=X&risk_only=1` | Sertifikat TLS dengan anomali |

---

## Instalasi

### Prasyarat

- Docker dan Docker Compose
- Sistem operasi: Ubuntu 20.04+ / Debian / Kali Linux
- RAM minimum: 4 GB (disarankan 8 GB+)

### Langkah Instalasi

```bash
# 1. Clone repository
git clone <url-repo-ini> reNgine-Custom && cd reNgine-Custom

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
cd reNgine-Custom && sudo ./update.sh
```

---

## Riwayat Pembaruan

Semua perubahan dilacak melalui git. Tabel di bawah mencatat riwayat commit sejak fork dimulai.

| Commit | Tanggal | Perubahan |
|--------|---------|-----------|
| `f1a1e94` | 2026-03-09 | feat(osint): tambah HUMINT dan SIGINT, 7 model baru, migrasi 0005, 7 API endpoint baru |
| `e455064` | 2026-03-09 | fix: perbaiki cakupan DAST CVE, tambah 2024, gunakan dir induk dast/cves/ |
| `c9fe1c6` | 2026-03-09 | fix: hapus duplikat httpx; tambah 249 template DAST nuclei; proxy auto-fetch untuk GooFuzz |
| `01584e6` | 2026-03-09 | fix: cegah scan stuck di "In Progress"; perbaiki visibilitas kolom screenshot |
| `fd8e196` | 2026-03-08 | fix(dorking): deteksi blokir IP GooFuzz lalu skip; perbaiki tab screenshot; tambah bing ke theHarvester |
| `5261844` | 2026-03-08 | feat: tambah task fetch_free_proxies (scrape proxy gratis dari 4 sumber) + tombol UI |
| `67c7022` | 2026-03-08 | fix: crash osint job.get() dengan allow_join_result(); perbaiki log domain tidak valid |
| `5e9752f` | 2026-03-08 | fix(osint): gunakan sumber theHarvester gratis saja (bukan -b all) |
| `bc40df0` | 2026-03-08 | fix(deps): perbaiki konflik versi tenacity dengan langchain_core |
| `ca742bd` | 2026-03-08 | fix(osint): perbaikan integrasi tool OSINT; nonaktifkan notifikasi update dari upstream reNgine |
| `73ef07b` | 2026-03-07 | fix(osint): pin GooFuzz ke v1.2.6; tambah jq ke Dockerfile |
| `a55bf8c` | 2026-03-07 | fix: perbaikan integrasi Ollama, report generation, dan beberapa fungsi umum |
| `b81c587` | 2026-03-02 | fix: perbaikan konfigurasi Docker Compose (network binding, healthcheck) |
| `b8601d5` | 2026-02-28 | fix: report generation 500 error (pin pydyf); perbaiki OpenAI module import |
| `b97625c` | 2026-02-28 | feat: optimalkan Gunicorn; satukan network binding ke 0.0.0.0; tutup 7 celah keamanan HIGH |
| `dc1efef` | 2026-02-28 | fix(gunicorn): naikkan limit-request-line ke 8190 untuk DataTables dengan query panjang |
| `49e8e06` | 2026-02-27 | feat: fork awal reNgine-Custom; audit keamanan 27 temuan (2 CRITICAL, 7 HIGH, 10 MEDIUM, 8 LOW), semua diperbaiki; hardening Nginx |

### Ringkasan Keamanan (Audit Awal)

| Tingkat | Jumlah | Status |
|---------|--------|--------|
| CRITICAL | 2 | Semua diperbaiki |
| HIGH | 7 | Semua diperbaiki |
| MEDIUM | 10 | Semua diperbaiki |
| LOW | 8 | Semua diperbaiki |
| **Total** | **27** | **Semua diperbaiki** |

Detail lengkap tersedia di [RENGINE_DEEP_AUDIT_V2.md](RENGINE_DEEP_AUDIT_V2.md).

---

Lisensi: [GPLv3](LICENSE)
