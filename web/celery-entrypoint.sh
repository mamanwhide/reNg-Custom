#!/bin/bash
# NOTE: Do NOT use 'set -e' here! Tool installations may fail (e.g. theHarvester)
# but should not prevent Celery workers from starting. Each install step uses
# '|| true' to handle failures gracefully.

# ── Network availability check ──────────────────────────────────────────────
# If we can't reach PyPI, skip ALL network-dependent installations.
# This prevents multi-hour pip retry loops when running without internet
# (e.g. VPN-only environments, air-gapped networks).
NETWORK_AVAILABLE=false
if python3 -c "import socket; socket.setdefaulttimeout(5); socket.getaddrinfo('pypi.org', 443)" 2>/dev/null; then
  NETWORK_AVAILABLE=true
  echo "Network available — will install/update external tools"
else
  echo "WARNING: No internet access (DNS resolution failed for pypi.org)"
  echo "Skipping external tool installation — using pre-installed tools only"
  echo "Celery workers will start immediately"
fi

# Common pip flags to prevent long retries when network is flaky
PIP_NETWORK_FLAGS="--retries 1 --timeout 15"

# NOTE: tenacity upgrade is done AFTER all tool installations below
# (theHarvester pins tenacity==8.0.1 which would overwrite an early upgrade)

# Wait for web container to finish migrations instead of running them concurrently
echo "Waiting for database migrations to be applied by web container..."
until python3 -c "
import django, sys, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'paraKang.settings')
django.setup()
from django.db import connection
cursor = connection.cursor()
cursor.execute(\"SELECT 1 FROM information_schema.tables WHERE table_name='auth_user'\")
if not cursor.fetchone():
    sys.exit(1)
" 2>/dev/null; do
  echo "Migrations not yet applied, waiting 5 seconds..."
  sleep 5
done
echo "Migrations are ready!"


python3 manage.py collectstatic --no-input

# Load default engines, keywords, and external tools (hanya jika belum ada data)
ENGINE_COUNT=$(python3 manage.py shell -c "from scanEngine.models import EngineType; print(EngineType.objects.count())" 2>/dev/null | tail -1)
if [ "$ENGINE_COUNT" = "0" ]; then
  python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
else
  echo "Scan engines already loaded ($ENGINE_COUNT engines), skipping."
fi

KEYWORD_COUNT=$(python3 manage.py shell -c "from scanEngine.models import InterestingLookupModel; print(InterestingLookupModel.objects.count())" 2>/dev/null | tail -1)
if [ "$KEYWORD_COUNT" = "0" ]; then
  python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
else
  echo "Keywords already loaded ($KEYWORD_COUNT keywords), skipping."
fi

TOOL_COUNT=$(python3 manage.py shell -c "from scanEngine.models import InstalledExternalTool; print(InstalledExternalTool.objects.count())" 2>/dev/null | tail -1)
if [ "$TOOL_COUNT" = "0" ]; then
  python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool
else
  echo "External tools already loaded ($TOOL_COUNT tools), skipping."
fi

# install firefox https://askubuntu.com/a/1404401
if [ "$NETWORK_AVAILABLE" = true ]; then
  echo '
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001

Package: firefox
Pin: version 1:1snap1-0ubuntu2
Pin-Priority: -1
' | tee /etc/apt/preferences.d/mozilla-firefox
  apt update || true
  apt install firefox -y || true
else
  echo "Skipping Firefox install (no network)"
fi

# Temporary fix for whatportis bug - See https://github.com/mamanwhide/paraKang/issues/984
WHATPORTIS_CLI=$(python3 -c "import whatportis.cli; print(whatportis.cli.__file__)" 2>/dev/null) || true
if [ -n "$WHATPORTIS_CLI" ]; then
  sed -i 's/purge()/truncate()/g' "$WHATPORTIS_CLI" || true
fi

# update whatportis
yes | whatportis --update || true

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]
then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ "$NETWORK_AVAILABLE" = true ]; then
  if [ ! -f "/usr/src/wordlist/dicc.txt" ]
  then
    echo "Downloading Default Directory Bruteforce Wordlist"
    timeout 30 wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt || true
  fi

  # check if default wordlist for amass exists
  if [ ! -f /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt ];
  then
    echo "Downloading Deepmagic top 50000 Wordlist"
    timeout 30 wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt || true
  fi

  # clone Sublist3r
  if [ ! -d "/usr/src/github/Sublist3r" ]
  then
    echo "Cloning Sublist3r"
    timeout 60 git clone https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r || true
  fi
  python3 -m pip install $PIP_NETWORK_FLAGS -r /usr/src/github/Sublist3r/requirements.txt || true

  # clone OneForAll
  if [ ! -d "/usr/src/github/OneForAll" ]
  then
    echo "Cloning OneForAll"
    timeout 60 git clone https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll || true
  fi
  python3 -m pip install $PIP_NETWORK_FLAGS -r /usr/src/github/OneForAll/requirements.txt || true

  # clone eyewitness
  if [ ! -d "/usr/src/github/EyeWitness" ]
  then
    echo "Cloning EyeWitness"
    timeout 60 git clone https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness || true
  fi

  # clone theHarvester
  if [ ! -d "/usr/src/github/theHarvester" ]
  then
    echo "Cloning theHarvester"
    timeout 60 git clone https://github.com/laramies/theHarvester /usr/src/github/theHarvester || true
  fi
  # theHarvester changed their repo structure - try multiple possible requirement paths
  if [ -f "/usr/src/github/theHarvester/requirements/base.txt" ]; then
    python3 -m pip install $PIP_NETWORK_FLAGS -r /usr/src/github/theHarvester/requirements/base.txt || true
  elif [ -f "/usr/src/github/theHarvester/requirements.txt" ]; then
    python3 -m pip install $PIP_NETWORK_FLAGS -r /usr/src/github/theHarvester/requirements.txt || true
  else
    echo "WARNING: theHarvester requirements file not found, skipping installation"
  fi
else
  echo "Skipping tool cloning/installation (no network)"
fi

# clone vulscan
if [ "$NETWORK_AVAILABLE" = true ]; then
  if [ ! -d "/usr/src/github/scipag_vulscan" ]
  then
    echo "Cloning Nmap Vulscan script"
    timeout 60 git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan || true
    echo "Symlinking to nmap script dir"
    ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan || true
    echo "Usage in paraKang, set vulscan/vulscan.nse in nmap_script scanEngine port_scan config parameter"
  fi

  # install h8mail
  python3 -m pip install $PIP_NETWORK_FLAGS h8mail || true

  # install gf patterns
  if [ ! -d "/root/Gf-Patterns" ];
  then
    echo "Installing GF Patterns"
    mkdir -p ~/.gf
    cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json ~/.gf 2>/dev/null || true
    timeout 60 git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns || true
    mv ~/Gf-Patterns/*.json ~/.gf 2>/dev/null || true
  fi
else
  echo "Skipping vulscan/h8mail/gf-patterns install (no network)"
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu && subfinder && amass || true
nuclei || true

if [ "$NETWORK_AVAILABLE" = true ]; then
  if [ ! -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
  then
    echo "Installing Geeknik Nuclei templates"
    timeout 60 git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates || true
  fi

  if [ ! -f ~/nuclei-templates/ssrf_nagli.yaml ];
  then
    echo "Downloading ssrf_nagli for Nuclei"
    timeout 30 wget https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O ~/nuclei-templates/ssrf_nagli.yaml || true
  fi

  if [ ! -d "/usr/src/github/CMSeeK" ]
  then
    echo "Cloning CMSeeK"
    timeout 60 git clone https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK || true
    pip install $PIP_NETWORK_FLAGS -r /usr/src/github/CMSeeK/requirements.txt || true
  fi

  # clone ctfr
  if [ ! -d "/usr/src/github/ctfr" ]
  then
    echo "Cloning CTFR"
    timeout 60 git clone https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr || true
  fi

  # clone gooFuzz (pinned to v1.2.6 — v2.0 requires Google Custom Search API keys)
  if [ ! -d "/usr/src/github/goofuzz" ]
  then
    echo "Cloning GooFuzz v1.2.6"
    timeout 60 git clone --branch 1.2.6 --depth 1 https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz || true
    chmod +x /usr/src/github/goofuzz/GooFuzz 2>/dev/null || true
  else
    # If already cloned, ensure we're on v1.2.6 (not v2.0 which needs API keys)
    GOOFUZZ_VERSION=$(cd /usr/src/github/goofuzz && grep -m1 'version=' GooFuzz 2>/dev/null | grep -oP '\"[0-9.]+\"' | tr -d '"')
    if [ "$GOOFUZZ_VERSION" = "2.0" ]; then
      echo "GooFuzz v2.0 detected, downgrading to v1.2.6..."
      rm -rf /usr/src/github/goofuzz
      timeout 60 git clone --branch 1.2.6 --depth 1 https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz || true
      chmod +x /usr/src/github/goofuzz/GooFuzz 2>/dev/null || true
    fi
  fi
else
  echo "Skipping nuclei templates/CMSeeK/ctfr/goofuzz install (no network)"
fi

# httpx seems to have issue, use alias instead!!!
echo 'alias httpx="/go/bin/httpx"' >> ~/.bashrc

# TEMPORARY FIX, httpcore is causing issues with celery, removing it as temp fix
#python3 -m pip uninstall -y httpcore

# Fix tenacity version: langchain_core needs >=8.2.3, but theHarvester pins 8.0.1.
# Must run AFTER all tool installations to avoid being overwritten.
if [ "$NETWORK_AVAILABLE" = true ]; then
  pip3 install --quiet --upgrade $PIP_NETWORK_FLAGS 'tenacity>=8.2.3,!=8.4.0,<9.0.0' 2>/dev/null || true
fi

loglevel='info'
if [ "$DEBUG" == "1" ]; then
    loglevel='debug'
fi

echo "Starting Celery Workers..."

# ─────────────────────────────────────────────────────────────────────
# CONSOLIDATED WORKER LAYOUT (6 processes instead of 22)
#
# Memory savings: ~3.2 GB (16 fewer Python/Django processes × ~200MB)
#
# Worker 1: main_scan     (prefork) — heavy CPU-bound scan tasks
# Worker 2: api           (gevent)  — API shared tasks
# Worker 3: orchestration (gevent)  — scan lifecycle: initiate, subscan, report
# Worker 4: notification  (gevent)  — all notification channels
# Worker 5: osint         (gevent)  — OSINT/recon tasks
# Worker 6: utility       (gevent)  — lightweight helpers: nmap parse, geo, whois, llm, etc.
# ─────────────────────────────────────────────────────────────────────

# Helper to start a gevent worker listening on multiple queues
start_consolidated_worker() {
    local queues=$1
    local concurrency=$2
    local worker_name=$3

    if [ "$DEBUG" == "1" ]; then
        watchmedo auto-restart --recursive --pattern="*.py" --directory="/usr/src/app/paraKang/" -- \
            celery -A paraKang.tasks worker --pool=gevent --optimization=fair \
            --autoscale=$concurrency,1 --loglevel=$loglevel -Q "$queues" -n "$worker_name" &
    else
        celery -A paraKang.tasks worker --pool=gevent --optimization=fair \
            --autoscale=$concurrency,1 --loglevel=$loglevel -Q "$queues" -n "$worker_name" &
    fi
}

# 1. Main scan worker (prefork) — nuclei, nmap, httpx, dalfox, etc.
if [ "$DEBUG" == "1" ]; then
    watchmedo auto-restart --recursive --pattern="*.py" --directory="/usr/src/app/paraKang/" -- \
        celery -A paraKang.tasks worker --loglevel=$loglevel --optimization=fair \
        --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &
else
    celery -A paraKang.tasks worker --loglevel=$loglevel --optimization=fair \
        --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &
fi

# 2. API shared task worker
if [ "$DEBUG" == "1" ]; then
    watchmedo auto-restart --recursive --pattern="*.py" --directory="/usr/src/app/api/" -- \
        celery -A api.shared_api_tasks worker --pool=gevent --optimization=fair \
        --concurrency=20 --loglevel=$loglevel -Q api_queue -n api_worker &
else
    celery -A api.shared_api_tasks worker --pool=gevent --concurrency=20 \
        --optimization=fair --loglevel=$loglevel -Q api_queue -n api_worker &
fi

# 3. Orchestration worker — scan lifecycle
start_consolidated_worker \
    "initiate_scan_queue,subscan_queue,report_queue" \
    20 "orchestration_worker"

# 4. Notification worker — all notification channels
start_consolidated_worker \
    "send_notif_queue,send_task_notif_queue,send_scan_notif_queue,send_file_to_discord_queue,send_hackerone_report_queue" \
    10 "notification_worker"

# 5. OSINT worker — dorking, theHarvester, h8mail, osint_discovery
start_consolidated_worker \
    "osint_discovery_queue,dorking_queue,theHarvester_queue,h8mail_queue" \
    15 "osint_worker"

# 6. Utility worker — nmap parse, geo, whois, dedup, run_command, llm
start_consolidated_worker \
    "parse_nmap_results_queue,geo_localize_queue,query_whois_queue,query_reverse_whois_queue,query_ip_history_queue,remove_duplicate_endpoints_queue,run_command_queue,llm_queue" \
    20 "utility_worker"

# Wait for all background workers
wait