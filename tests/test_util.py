import asyncio
import threading

from threema.gateway import util


def _run_in_thread(func):
    # A new thread has no current event loop on any Python version.
    result = {}

    def target():
        result['value'] = func()
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        asyncio.set_event_loop(None)
        loop.close()

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    return result['value']


class TestAioRun:
    def test_reuses_event_loop(self):
        @util.aio_run
        async def get_loop():
            return asyncio.get_running_loop()

        first, second = _run_in_thread(lambda: (get_loop(), get_loop()))
        assert first is second
