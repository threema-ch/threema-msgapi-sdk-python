"""
Utility functions.
"""
import asyncio
import collections
import functools
import inspect
import io
import logging
import os
from typing import Set  # noqa

import libnacl
import logbook
import logbook.compat
import logbook.more
# noinspection PyPackageRequirements
import lru
import wrapt

from .key import Key

__all__ = (
    'enable_logging',
    'disable_logging',
    'get_logger',
    'read_key_or_key_file',
    'raise_server_error',
    'randint',
    'ViewIOReader',
    'ViewIOWriter',
    'async_lru_cache',
    'aio_run',
    'aio_run_decorator',
    'aio_run_proxy_decorator',
    'AioRunMixin',
)

_logger_group = logbook.LoggerGroup()
_logger_group.disabled = True
_logger_redirect_handler = logbook.compat.RedirectLoggingHandler()
_logger_convert_level_handler = logbook.compat.LoggingHandler()


def _convert_level(logging_level):
    return _logger_convert_level_handler.convert_level(logging_level)


def enable_logging(level=logbook.WARNING, asyncio_level=None, aiohttp_level=None):
    # Determine levels
    level = logbook.lookup_level(level)
    converted_level = _convert_level(level)
    if asyncio_level is None:
        asyncio_level = converted_level
    else:
        asyncio_level = _convert_level(asyncio_level)
    if aiohttp_level is None:
        aiohttp_level = converted_level
    else:
        aiohttp_level = _convert_level(aiohttp_level)

    # Enable logger group
    _logger_group.disabled = False

    # Enable asyncio debug logging
    os.environ['PYTHONASYNCIODEBUG'] = '1'

    # Redirect asyncio logger
    logger = logging.getLogger('asyncio')
    logger.setLevel(asyncio_level)
    logger.addHandler(_logger_redirect_handler)

    # Redirect aiohttp logger
    logger = logging.getLogger('aiohttp')
    logger.setLevel(aiohttp_level)
    logger.addHandler(_logger_redirect_handler)


def disable_logging():
    # Reset aiohttp logger
    logger = logging.getLogger('aiohttp')
    logger.removeHandler(_logger_redirect_handler)
    logger.setLevel(logging.NOTSET)

    # Reset asyncio logger
    logger = logging.getLogger('asyncio')
    logger.removeHandler(_logger_redirect_handler)
    logger.setLevel(logging.NOTSET)

    # Disable asyncio debug logging
    del os.environ['PYTHONASYNCIODEBUG']

    # Disable logger group
    _logger_group.disabled = True


def get_logger(name=None, level=logbook.NOTSET):
    """
    Return a :class:`logbook.Logger`.

    Arguments:
        - `name`: The name of a specific sub-logger.
    """
    base_name = 'threema.gateway'
    name = base_name if name is None else '.'.join((base_name, name))

    # Create new logger and add to group
    logger = logbook.Logger(name=name, level=level)
    _logger_group.add_logger(logger)
    return logger


# TODO: Raises
def read_key_or_key_file(key, expected_type):
    """
    Decode a hex-encoded key or read it from a file.

    Arguments:
        - `key`: A hex-encoded key or the name of a file which contains
          a key.
        - `expected_type`: One of the types of :class:`Key.Type`.

    Return a:class:`libnacl.public.SecretKey` or
    :class:`libnacl.public.PublicKey` instance.
    """
    # Read key file (if any)
    try:
        with open(key) as file:
            key = file.readline().strip()
    except IOError:
        pass

    # Convert to key instance
    return Key.decode(key, expected_type)


async def raise_server_error(response, error):
    """
    Raise a :class:`GatewayServerError` exception from a
    HTTP response. Releases the response before raising.


    Arguments:
        - `response`: A :class:`aiohttp.ClientResponse` instance.
        - `error`: The :class:`GatewayServerError`. to instantiate.

    Always raises :class:`GatewayServerError`.
    """
    status = response.status
    await response.release()
    raise error(status)


def randint(a, b):
    """
    Return a cryptographically secure random integer N such that
    ``a <= N <= b``.
    """
    n = libnacl.randombytes_uniform(b) + a
    assert a <= n <= b
    return n


# TODO: Document properly
class ViewIOReader(io.RawIOBase):
    def __init__(self, bytes_or_view):
        super().__init__()
        if isinstance(bytes_or_view, bytes):
            bytes_or_view = memoryview(bytes_or_view)
        self._view = bytes_or_view
        self._offset = 0
        self._length = len(self._view)

    # IOBase methods

    def fileno(self):
        raise OSError('No file descriptors used')

    def isatty(self):
        return False

    def readable(self):
        return True

    def readline(self, size=-1):
        raise NotImplementedError

    def readlines(self, hint=-1):
        raise NotImplementedError

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            pass
        elif whence == os.SEEK_CUR:
            offset += self._offset
        elif whence == os.SEEK_END:
            offset = self._length - offset
        else:
            raise ValueError('Invalid whence value')
        if not 0 < offset <= self._length:
            raise ValueError('Offset is greater than view length')
        self._offset = offset
        return offset

    def seekable(self):
        return True

    def tell(self):
        return self._offset

    def writable(self):
        return False

    # RawIOBase methods

    def read(self, size=-1):
        if size == -1:
            return self.readall()
        elif size < 0:
            raise ValueError('Negative size')
        start, end = self._offset, min(self._offset + size, self._length)
        self._offset = end
        return self._view[start:end]

    def readall(self):
        return self.read(self._length - self._offset)

    def readinto(self, b):
        data = self.readall()
        b.extend(data)
        return len(data)

    # Custom methods

    def __len__(self):
        return self._length - self._offset

    def readexactly(self, size):
        data = self.read(size)
        if len(data) < size:
            raise asyncio.IncompleteReadError(data, size)
        else:
            return data


# TODO: Document properly
class ViewIOWriter(io.RawIOBase):
    def __init__(self, bytes_or_views=None):
        super().__init__()
        self._views = []
        self._length = 0
        if bytes_or_views is not None:
            for bytes_or_view in bytes_or_views:
                self.writeexactly(bytes_or_view)

    # IOBase methods

    def fileno(self):
        raise OSError('No file descriptors used')

    def isatty(self):
        return False

    def readable(self):
        return False

    def seekable(self):
        return False

    def writable(self):
        return True

    # RawIOBase methods

    def write(self, bytes_or_view):
        # Convert to memoryview if necessary
        if isinstance(bytes_or_view, bytes):
            bytes_or_view = memoryview(bytes_or_view)

        # Append
        length = len(bytes_or_view)
        self._length += length
        self._views.append(bytes_or_view)
        return length

    def writelines(self, lines):
        raise NotImplementedError

    # Custom methods

    def __radd__(self, other):
        self.extend(other)
        return self

    def __len__(self):
        return self._length

    def getvalue(self):
        return b''.join(self._views)

    # noinspection PyProtectedMember
    def extend(self, other):
        self._views += other._views
        self._length += other._length

    def writeexactly(self, bytes_or_view):
        return self.write(bytes_or_view)


class _HashedSeq(list):
    """
    This class guarantees that hash() will be called no more than once
    per element.  This is important because the lru_cache() will hash
    the key multiple times on a cache miss.
    """
    __slots__ = 'hash_value'

    # noinspection PyMissingConstructor
    def __init__(self, tuple_):
        self[:] = tuple_
        self.hash_value = hash(tuple_)

    def __hash__(self):
        return self.hash_value


# noinspection PyPep8Naming
_CacheInfo = collections.namedtuple(
    'CacheInfo', ('hits', 'misses', 'maxsize', 'currsize'))


def _make_key(
    args, kwargs, typed,
    fast_types={int, str, frozenset, type(None)},
    kwargs_mark=(object(),),
):
    """
    Make a cache key from optionally typed positional and keyword arguments

    The key is constructed in a way that is flat as possible rather than
    as a nested structure that would take more memory.

    If there is only a single argument and its data type is known to cache
    its hash value, then that argument is returned without a wrapper.  This
    saves space and improves lookup speed.
    """
    key = args
    if kwargs:
        sorted_items = sorted(kwargs.items())
        key += kwargs_mark
        for item in sorted_items:
            key += item
    else:
        sorted_items = []
    if typed:
        key += tuple(type(v) for v in args)
        if kwargs:
            key += tuple(type(v) for k, v in sorted_items)
    elif len(key) == 1 and type(key[0]) in fast_types:
        return key[0]
    return _HashedSeq(key)


class _LRUCacheDict(lru.LRUCacheDict):
    def __init__(self, *args, **kwargs):
        self.hits = self.misses = 0
        super().__init__(*args, **kwargs)

    def __len__(self):
        return self.size()

    def info(self):
        """Report cache statistics"""
        return _CacheInfo(self.hits, self.misses, self.max_size, len(self))

    def __getitem__(self, key):
        try:
            item = super().__getitem__(key)
        except KeyError:
            self.misses += 1
            raise
        else:
            self.hits += 1
            return item

    def clear(self):
        super().clear()
        self.hits = self.misses = 0


def async_lru_cache(maxsize=1024, expiration=15 * 60, typed=False):
    """
    Least-recently-used cache decorator for asyncio coroutines.

    If *maxsize* is set to None, the LRU features are disabled and the
    cache can grow without bound.

    If *expiration* is set, cached values will be cleared after
    *expiration* seconds.

    If *typed* is True, arguments of different types will be cached
    separately. For example, f(3.0) and f(3) will be treated as distinct
    calls with distinct results.

    Arguments to the cached function must be hashable.

    View the cache statistics named tuple (hits, misses, maxsize,
    currsize) with f.cache_info().  Clear the cache and statistics
    with f.cache_clear(). Access the underlying function with
    f.__wrapped__.

    See:  http://en.wikipedia.org/wiki/Cache_algorithms#Least_Recently_Used
    """

    def decorating_function(func):
        cache = _LRUCacheDict(max_size=maxsize, expiration=expiration)

        async def wrapper(*args, **kwargs):
            # Make cached key
            key = _make_key(args, kwargs, typed)

            # Get from cache
            try:
                return cache[key]
            except KeyError:
                pass

            # Miss, retrieve from coroutine
            value = await func(*args, **kwargs)
            cache[key] = value
            return value

        wrapper.cache = cache
        wrapper.cache_info = cache.info
        wrapper.cache_clear = cache.clear

        return functools.update_wrapper(wrapper, func)

    return decorating_function


def aio_run(coroutine, loop=None, close_after_complete=False):
    """
    Decorator to run an asyncio coroutine as a normal blocking
    function.

    Arguments:
        - `coroutine`: The asyncio coroutine or task to be executed.
        - `loop`: An optional :class:`asyncio.AbstractEventLoop`
          subclass instance.
        - `close_after_complete`: Close `loop` after the coroutine
          returned. Defaults to ``False``.

    Returns the result of the asyncio coroutine.

    Example:

    .. code-block::
        async def coroutine(timeout):
            await asyncio.sleep(timeout)
            return True

        # Call coroutine in a blocking manner
        result = aio_run(coroutine(1.0))
        print(result)
    """

    # Create a new event loop (if required)
    if loop is None:
        loop_ = asyncio.get_event_loop()

        # Closed? Set a new one
        if loop_.is_closed():
            loop_ = asyncio.new_event_loop()
            asyncio.set_event_loop(loop_)
    else:
        loop_ = loop

    # Run the coroutine and get the result
    result = loop_.run_until_complete(coroutine)

    # Close loop (if requested)
    if close_after_complete:
        loop_.close()

    # Return the result
    return result


def aio_run_decorator(loop=None, close_after_complete=False):
    """
    Decorator to run an asyncio coroutine as a normal blocking
    function.

    Arguments:
        - `loop`: An optional :class:`asyncio.AbstractEventLoop`
          subclass instance.
        - `close_after_complete`: Close `loop` after the coroutine
          returned. Defaults to ``False``.

    Returns a decorator to wrap around an asyncio coroutine.

    Example:

    .. code-block::
        async def coroutine(timeout):
            await asyncio.sleep(timeout)
            return True

        @aio_run_decorator()
        async def helper(*args, **kwargs):
            return await coroutine(*args, **kwargs)

        # Call coroutine in a blocking manner
        result = helper(timeout=1.0)
        print(result)
    """
    def _decorator(func):
        # Make it a coroutine if it isn't one already
        if not asyncio.iscoroutinefunction(func):
            func = asyncio.coroutine(func)

        def _wrapper(*args, **kwargs):
            return aio_run(
                func(*args, **kwargs),
                loop=loop,
                close_after_complete=close_after_complete,
            )
        return functools.update_wrapper(_wrapper, func)
    return _decorator


def aio_run_proxy_decorator(cls):
    """
    Proxy a publicly accessible class and run all methods marked as
    async inside it (using the class attribute `async_functions`) with
    an event loop to make it appear as a traditional blocking method.

    Arguments:
        - `cls`: A class to be wrapped. The class must inherit
          :class:`AioRunMixin`. The class and all base classes must
          supply a class attribute `async_functions` which is an
          iterable of method names that should appear as traditional
          blocking functions from the outside.

    Returns a class factory.

    .. note:: The `unwrap` property of the resulting instance can be
              used to get the original instance.
    """
    # Ensure each base class has added a class-level iterable of async functions
    async_functions = set()
    for base_class in inspect.getmro(cls)[:-1]:
        try:
            async_functions.update(base_class.__dict__.get('async_functions', None))
        except TypeError:
            message = "Class {} is missing 'async_functions' iterable"
            raise ValueError(message.format(base_class.__name__))

    # Sanity-check
    if not issubclass(cls, AioRunMixin):
        raise TypeError("Class {} did not inherit 'AioRunMixin'".format(
            cls.__name__))

    class _AioRunProxyDecoratorFactory(wrapt.ObjectProxy):
        def __call__(self, *args, **kwargs):
            # Create instance
            instance = cls(*args, **kwargs)

            # Sanity-check
            if not isinstance(instance, AioRunMixin):
                raise TypeError("Class {} did not inherit 'AioRunMixin'".format(
                    cls.__name__))

            # Wrap with proxy (if required)
            if instance.blocking:
                class _AioRunProxy(wrapt.ObjectProxy):
                    @property
                    def unwrap(self):
                        """
                        Get the wrapped instance.
                        """
                        return self.__wrapped__

                # Wrap all async functions with `aio_run`
                for name in async_functions:
                    def _method(instance_, name_, *args_, **kwargs_):
                        method = aio_run_decorator()(getattr(instance_, name_))
                        return method(*args_, **kwargs_)

                    _method = functools.partial(_method, instance, name)
                    setattr(_AioRunProxy, name, _method)

                return _AioRunProxy(instance)
            else:
                return instance

    return _AioRunProxyDecoratorFactory(cls)


class AioRunMixin:
    """
    Must be inherited when using :func:`aio_run_proxy_decorator`.

    Arguments:
        - `blocking`: Switch to turn the blocking API on or off.
    """
    async_functions = set()  # type: Set[str]

    def __init__(self, blocking=False):
        self.blocking = blocking

    @property
    def unwrap(self):
        """
        Get the wrapped instance.
        """
        return self
