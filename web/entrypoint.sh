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
if command -v gosu &> /dev/null && id -u rengine &> /dev/null; then
    chown -R rengine:rengine /var/log/gunicorn 2>/dev/null || true
    exec gosu rengine gunicorn reNgine.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers "${GUNICORN_WORKERS:-4}" \
        --threads "${GUNICORN_THREADS:-2}" \
        --timeout 300 \
        --graceful-timeout 30 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --limit-request-line 8190 \
        --access-logfile /var/log/gunicorn/access.log \
        --error-logfile /var/log/gunicorn/error.log \
        --log-level info
else
    echo "[WARN] gosu or rengine user not found, running as current user"
    exec gunicorn reNgine.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers "${GUNICORN_WORKERS:-4}" \
        --threads "${GUNICORN_THREADS:-2}" \
        --timeout 300 \
        --graceful-timeout 30 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --limit-request-line 8190 \
        --access-logfile /var/log/gunicorn/access.log \
        --error-logfile /var/log/gunicorn/error.log \
        --log-level info
fi
