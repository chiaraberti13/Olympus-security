#!/usr/bin/env python3
"""Celery application configuration for async scan processing."""
from __future__ import annotations

from celery import Celery

from config import settings


celery_app = Celery(
    "vap",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["tasks"],
)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_queue=settings.celery_default_queue,
    task_default_exchange_type="direct",
    task_default_routing_key=settings.celery_default_queue,
    task_time_limit=settings.celery_task_time_limit,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    result_expires=settings.celery_result_expires_seconds,
)


def check_broker_connection() -> bool:
    """Return True if the Celery broker (Redis) is reachable."""
    try:
        conn = celery_app.connection_for_write()
        conn.ensure_connection(max_retries=1, timeout=2)
        conn.release()
        return True
    except Exception:
        return False
