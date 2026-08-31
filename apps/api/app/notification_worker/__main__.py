"""Run with: ``uv run python -m app.notification_worker`` from apps/api."""

from __future__ import annotations

import logging
import signal
import time

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.db import engine
from app.core.logging import bind_log_context, configure_logging
from app.services.email_provider import build_email_provider
from app.services.findings.follow_up_reminders import process_one_follow_up_reminder
from app.services.notification_runtime import (
    NotificationWorkerNotReady,
    email_delivery_readiness,
    process_one_email_delivery,
)
from app.services.reports.delivery import (
    process_one_delivery_intent,
    process_one_report_delivery_email,
)
from app.services.reports.delivery_crypto import report_delivery_crypto_ready

logger = logging.getLogger("scout.notification_worker")


class _Shutdown:
    stop = False


def _handle_signal(signum, _frame) -> None:
    logger.info(
        "shutdown signal received",
        extra={"event": "notification_worker.shutdown_signal", "signal": signum},
    )
    _Shutdown.stop = True


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    bind_log_context(worker="notification_worker")

    poll_interval = float(settings.notification_worker_poll_interval)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = build_email_provider(settings)
    consecutive_errors = 0

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(
        "starting notification worker",
        extra={
            "event": "notification_worker.start",
            "poll_interval": poll_interval,
            "environment": settings.environment,
            "email_delivery_enabled": settings.email_delivery_enabled,
            "email_provider": settings.email_provider,
        },
    )

    while not _Shutdown.stop:
        try:
            readiness = email_delivery_readiness(settings)
            if readiness.status == "paused":
                consecutive_errors = 0
                slept = 0.0
                while slept < poll_interval and not _Shutdown.stop:
                    time.sleep(min(0.25, poll_interval - slept))
                    slept += 0.25
                continue
            if readiness.status != "ready":
                logger.error(
                    "notification worker not ready; leaving pending rows pending",
                    extra={
                        "event": "notification_worker.not_ready",
                        "reason": readiness.reason,
                    },
                )
                consecutive_errors = 0
                time.sleep(poll_interval)
                continue

            crypto_ok, crypto_reason = report_delivery_crypto_ready(settings)
            if not crypto_ok:
                logger.error(
                    "report delivery not ready; leaving automatic report delivery pending",
                    extra={
                        "event": "notification_worker.report_delivery_not_ready",
                        "reason": crypto_reason,
                    },
                )

            did_work = False
            if crypto_ok:
                intent = process_one_delivery_intent(
                    session_factory, settings=settings
                )
                if intent is not None:
                    did_work = True
            row = process_one_email_delivery(
                session_factory, provider=provider, settings=settings
            )
            if row is not None:
                did_work = True
            reminder = process_one_follow_up_reminder(
                session_factory, provider=provider, settings=settings
            )
            if reminder is not None:
                did_work = True
            if crypto_ok:
                report_row = process_one_report_delivery_email(
                    session_factory, provider=provider, settings=settings
                )
                if report_row is not None:
                    did_work = True
            consecutive_errors = 0
            if not did_work:
                slept = 0.0
                while slept < poll_interval and not _Shutdown.stop:
                    time.sleep(min(0.25, poll_interval - slept))
                    slept += 0.25
        except NotificationWorkerNotReady as exc:
            consecutive_errors = 0
            logger.error(
                "notification worker not ready; leaving pending rows pending",
                extra={
                    "event": "notification_worker.not_ready",
                    "reason": exc.reason,
                },
            )
            time.sleep(poll_interval)
        except OperationalError:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "notification worker database error; backing off",
                extra={"event": "notification_worker.db_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)
        except Exception:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "notification worker loop error; backing off",
                extra={"event": "notification_worker.loop_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)

    logger.info("notification worker stopped", extra={"event": "notification_worker.stopped"})


if __name__ == "__main__":
    main()
