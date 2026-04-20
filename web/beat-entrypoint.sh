#!/bin/bash
set -e

# Fix dependency compatibility issues (needed for older images)
pip3 install --quiet --upgrade 'tenacity>=8.2.3,!=8.4.0,<9.0.0' 2>/dev/null || true

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

exec "$@"
