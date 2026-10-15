import asyncio
import threading
import warnings

import pytest

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


class TestAsyncTtlCache:
    def test_coroutine_function(self):
        async def get_value():
            return 1

        # asyncio.iscoroutinefunction() is deprecated since Python 3.14
        with warnings.catch_warnings():
            warnings.simplefilter('error', DeprecationWarning)
            cached = util.async_ttl_cache(ttl=60)(get_value)

        assert _run_in_thread(lambda: asyncio.run(cached())) == 1

    def test_not_a_coroutine_function(self):
        with pytest.raises(ValueError):
            util.async_ttl_cache(ttl=60)(lambda: 1)
