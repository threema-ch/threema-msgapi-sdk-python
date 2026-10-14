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


@util.aio_run_proxy
class _Counter(util.AioRunMixin):
    async_functions = {'increment'}

    def __init__(self, blocking=False):
        super().__init__(blocking=blocking)
        self.value = 0

    async def increment(self, by=1):
        await asyncio.sleep(0)
        self.value += by
        return self.value


class TestAioRunProxy:
    def test_blocking_methods(self):
        def run():
            counter = _Counter(blocking=True)
            return counter.increment(), counter.increment(by=2)

        assert _run_in_thread(run) == (1, 3)
