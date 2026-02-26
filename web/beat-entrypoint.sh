#!/bin/bash
set -e

# Fix dependency compatibility issues (needed for older images)
pip3 install --quiet --upgrade tenacity 2>/dev/null || true

python3 manage.py migrate

exec "$@"
