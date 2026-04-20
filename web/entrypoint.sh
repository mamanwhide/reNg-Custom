#!/bin/bash

# Fix dependency compatibility issues (needed for older images)
pip3 install --quiet --upgrade tenacity 2>/dev/null || true

# Apply database migrations
python3 manage.py migrate

# Collect static files
python3 manage.py collectstatic --no-input 2>/dev/null || true

# Create log directory
mkdir -p /var/log/gunicorn

# Drop privileges to non-root user if gosu is available
# Otherwise run as current user (backwards compatible with older images)
if command -v gosu &> /dev/null && id -u parakang &> /dev/null; then
    chown -R parakang:parakang /var/log/gunicorn 2>/dev/null || true
    exec gosu parakang gunicorn paraKang.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers "${GUNICORN_WORKERS:-4}" \
        --threads "${GUNICORN_THREADS:-2}" \
        --timeout 300 \
        --graceful-timeout 30 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --limit-request-line "${GUNICORN_LIMIT_REQUEST_LINE:-8190}" \
        --access-logfile /var/log/gunicorn/access.log \
        --error-logfile /var/log/gunicorn/error.log \
        --log-level info
else
    echo "[WARN] gosu or parakang user not found, running as $(whoami) — this is insecure for production!"
    echo "[WARN] Install gosu and create a parakang user to run as non-root"
    exec gunicorn paraKang.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers "${GUNICORN_WORKERS:-4}" \
        --threads "${GUNICORN_THREADS:-2}" \
        --timeout 300 \
        --graceful-timeout 30 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --limit-request-line "${GUNICORN_LIMIT_REQUEST_LINE:-8190}" \
        --access-logfile /var/log/gunicorn/access.log \
        --error-logfile /var/log/gunicorn/error.log \
        --log-level info
fi
