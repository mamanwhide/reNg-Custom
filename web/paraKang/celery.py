import os

import django
from celery import Celery
from celery.signals import setup_logging, worker_ready

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'paraKang.settings')
django.setup()

# Celery app
app = Celery('paraKang')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig
    dictConfig(app.conf['LOGGING'])


@worker_ready.connect()
def register_weekly_proxy_refresh(sender, **kwargs):
    """Auto-register the weekly proxy refresh Beat task in the DB the first
    time a worker comes online.  Uses get_or_create so it is idempotent —
    running multiple workers or restarting does not create duplicates."""
    import logging
    _log = logging.getLogger(__name__)
    try:
        from django_celery_beat.models import IntervalSchedule, PeriodicTask
        schedule, _ = IntervalSchedule.objects.get_or_create(
            every=7,
            period=IntervalSchedule.DAYS,
        )
        task, created = PeriodicTask.objects.get_or_create(
            name='Weekly proxy refresh & prune',
            defaults={
                'task': 'fetch_free_proxies',
                'interval': schedule,
                'args': '[]',
                'kwargs': '{"country_filter": null}',
                'enabled': True,
                'description': (
                    'Fetch fresh proxies from public sources, prune dead '
                    'entries, and save only live proxies. Runs weekly '
                    '(every 7 days) via Celery Beat DatabaseScheduler.'
                ),
            }
        )
        if created:
            _log.info('Celery Beat: registered "Weekly proxy refresh & prune" (every 7 days)')
        else:
            # Ensure it stays enabled even if someone disabled it
            if not task.enabled:
                task.enabled = True
                task.interval = schedule
                task.save(update_fields=['enabled', 'interval'])
                _log.info('Celery Beat: re-enabled "Weekly proxy refresh & prune"')
    except Exception as exc:
        _log.warning(f'register_weekly_proxy_refresh: could not register Beat task: {exc}')
