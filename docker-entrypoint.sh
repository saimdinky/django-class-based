#!/bin/bash

# Django Docker entrypoint script
# Production-ready startup script for Django Class-Based Views

set -e

echo "🚀 Starting Django Class-Based Views..."

# Wait for database to be ready
echo "⏳ Waiting for database..."
while ! nc -z ${DB_HOST:-localhost} ${DB_PORT:-3306}; do
  echo "Database is unavailable - sleeping"
  sleep 1
done

echo "✅ Database is ready!"

# Run database migrations
echo "🔄 Running database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "📦 Collecting static files..."
python manage.py collectstatic --noinput --clear

# Seed database if needed
if [ "${SEED_DATABASE:-false}" = "true" ]; then
  echo "🌱 Seeding database..."
  python manage.py seed_data
fi

# Create superuser if credentials are provided
if [ -n "${DJANGO_SUPERUSER_EMAIL}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD}" ]; then
  echo "👤 Creating superuser..."
  python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='${DJANGO_SUPERUSER_EMAIL}').exists():
    User.objects.create_superuser('${DJANGO_SUPERUSER_EMAIL}', '${DJANGO_SUPERUSER_PASSWORD}')
    print('Superuser created successfully')
else:
    print('Superuser already exists')
"
fi

echo "🎉 Django Class-Based Views is ready!"

# Start the application
if [ "${DJANGO_ENV:-production}" = "development" ]; then
  echo "🔧 Starting development server..."
  exec python manage.py runserver 0.0.0.0:8000
else
  echo "🚀 Starting production server..."
  exec gunicorn django_class_based.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers ${GUNICORN_WORKERS:-4} \
    --timeout ${GUNICORN_TIMEOUT:-30} \
    --keep-alive ${GUNICORN_KEEP_ALIVE:-2} \
    --max-requests ${GUNICORN_MAX_REQUESTS:-1000} \
    --max-requests-jitter ${GUNICORN_MAX_REQUESTS_JITTER:-100} \
    --log-level ${LOG_LEVEL:-info} \
    --access-logfile - \
    --error-logfile -
fi
