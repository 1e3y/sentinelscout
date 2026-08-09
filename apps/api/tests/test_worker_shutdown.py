from __future__ import annotations

import signal

from app.worker import __main__ as worker_main


def test_graceful_worker_shutdown_flag():
    worker_main._Shutdown.stop = False
    worker_main._handle_signal(signal.SIGTERM, None)
    assert worker_main._Shutdown.stop is True
    worker_main._Shutdown.stop = False
