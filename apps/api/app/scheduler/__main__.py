"""Run with: ``uv run python -m app.scheduler`` from apps/api."""

from __future__ import annotations

import logging
import signal
import time

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.db import engine
from app.core.logging import bind_log_context, clear_log_context, configure_logging
from app.services.scheduler_runtime import process_one_scheduled_monitoring

logger = logging.getLogger("scout.scheduler")


class _Shutdown:
    stop = False


def _handle_signal(signum, _frame) -> None:
    logger.info(
        "shutdown signal received",
        extra={"event": "scheduler.shutdown_signal", "signal": signum},
    )
    _Shutdown.stop = True


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    bind_log_context(worker="scheduler")

    poll_interval = float(settings.scheduler_poll_interval)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    consecutive_errors = 0

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(
        "starting monitoring scheduler",
        extra={
            "event": "scheduler.start",
            "poll_interval": poll_interval,
            "environment": settings.environment,
        },
    )

    while not _Shutdown.stop:
        try:
            operation = process_one_scheduled_monitoring(session_factory)
            consecutive_errors = 0
            if operation is None:
                slept = 0.0
                while slept < poll_interval and not _Shutdown.stop:
                    time.sleep(min(0.25, poll_interval - slept))
                    slept += 0.25
            else:
                bind_log_context(
                    operation_id=str(operation.id),
                    organization_id=str(operation.organization_id),
                    target_id=str(operation.target_id),
                )
                logger.info(
                    "scheduled operation created",
                    extra={
                        "event": "scheduler.operation_created",
                        "operation_id": str(operation.id),
                        "target_id": str(operation.target_id),
                    },
                )
                clear_log_context()
                bind_log_context(worker="scheduler")
        except OperationalError:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "scheduler database error; backing off",
                extra={"event": "scheduler.db_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)
        except Exception:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "scheduler loop error; backing off",
                extra={"event": "scheduler.loop_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)

    logger.info("monitoring scheduler stopped", extra={"event": "scheduler.stopped"})


if __name__ == "__main__":
    main()
