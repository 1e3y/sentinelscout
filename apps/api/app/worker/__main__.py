"""Run with: ``uv run python -m app.worker`` from apps/api."""

from __future__ import annotations

import logging
import signal
import time

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.db import engine
from app.core.logging import bind_log_context, clear_log_context, configure_logging
from app.services.discovery.runner import SubprocessDiscoveryTools
from app.services.retest_runtime import process_one_retest
from app.services.reports.auto import process_one_automatic_report
from app.services.validation_engine.http import HttpxSafeHttpClient
from app.services.validation_runtime import process_one_validation
from app.services.worker_runtime import process_one_operation

logger = logging.getLogger("scout.worker")


class _Shutdown:
    stop = False


def _handle_signal(signum, _frame) -> None:
    logger.info(
        "shutdown signal received",
        extra={"event": "worker.shutdown_signal", "signal": signum},
    )
    _Shutdown.stop = True


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    bind_log_context(worker="worker")

    poll_interval = float(settings.worker_poll_interval)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = SubprocessDiscoveryTools()
    http_client = HttpxSafeHttpClient()
    consecutive_errors = 0

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(
        "starting scout worker",
        extra={
            "event": "worker.start",
            "poll_interval": poll_interval,
            "environment": settings.environment,
        },
    )

    while not _Shutdown.stop:
        worked = False
        try:
            result = process_one_operation(session_factory, tools=tools)
            if result is not None:
                bind_log_context(
                    operation_id=str(result.id),
                    organization_id=str(result.organization_id),
                    target_id=str(result.target_id),
                )
                logger.info(
                    "processed operation",
                    extra={
                        "event": "worker.operation_processed",
                        "status": result.status,
                        "operation_id": str(result.id),
                    },
                )
                clear_log_context()
                bind_log_context(worker="worker")
                worked = True

            auto = process_one_automatic_report(session_factory)
            if auto is not None:
                bind_log_context(
                    operation_id=str(auto.operation_id),
                    organization_id=str(auto.organization_id),
                )
                logger.info(
                    "processed automatic report job",
                    extra={
                        "event": "worker.automatic_report_processed",
                        "status": auto.status,
                        "job_id": str(auto.id),
                        "operation_id": str(auto.operation_id),
                    },
                )
                clear_log_context()
                bind_log_context(worker="worker")
                worked = True

            if not worked:
                attempt = process_one_validation(session_factory, http_client=http_client)
                if attempt is not None:
                    bind_log_context(
                        operation_id=str(attempt.operation_id),
                        organization_id=str(attempt.organization_id),
                    )
                    logger.info(
                        "processed validation",
                        extra={
                            "event": "worker.validation_processed",
                            "status": attempt.status,
                            "operation_id": str(attempt.operation_id),
                        },
                    )
                    clear_log_context()
                    bind_log_context(worker="worker")
                    worked = True
                else:
                    retest = process_one_retest(session_factory, http_client=http_client)
                    if retest is not None:
                        bind_log_context(organization_id=str(retest.organization_id))
                        logger.info(
                            "processed retest",
                            extra={
                                "event": "worker.retest_processed",
                                "status": retest.status,
                            },
                        )
                        clear_log_context()
                        bind_log_context(worker="worker")
                        worked = True

            consecutive_errors = 0
            if not worked:
                # Sleep in small slices so SIGTERM is noticed quickly.
                slept = 0.0
                while slept < poll_interval and not _Shutdown.stop:
                    time.sleep(min(0.25, poll_interval - slept))
                    slept += 0.25
        except OperationalError:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "worker database error; backing off",
                extra={"event": "worker.db_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)
        except Exception:
            consecutive_errors += 1
            backoff = min(poll_interval * (2 ** min(consecutive_errors, 5)), 60.0)
            logger.exception(
                "worker loop error; backing off",
                extra={"event": "worker.loop_error", "backoff_seconds": backoff},
            )
            time.sleep(backoff)

    logger.info("scout worker stopped", extra={"event": "worker.stopped"})


if __name__ == "__main__":
    main()
