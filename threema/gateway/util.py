"""
Utility functions.
"""
import asyncio
import collections
import functools

import libnacl
# noinspection PyPackageRequirements
import lru

from .key import Key

__all__ = (
    'read_key_or_key_file',
    'raise_server_error',
    'randint',
    'async_lru_cache',
)


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


@asyncio.coroutine
def raise_server_error(response, error):
    """
    Raise a :class:`GatewayServerError` exception from a
    HTTP response. Releases the response before raising.


    Arguments:
        - `response`: A :class:`aiohttp.ClientResponse` instance.
        - `error`: The :class:`GatewayServerError`. to instantiate.

    Always raises :class:`GatewayServerError`.
    """
    status = response.status
    yield from response.release()
    raise error(status)


def randint(a, b):
    """
    Return a cryptographically secure random integer N such that
    ``a <= N <= b``.
    """
    n = libnacl.randombytes_uniform(b) + a
    assert a <= n <= b
    return n


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

        @asyncio.coroutine
        def wrapper(*args, **kwargs):
            # Make cached key
            key = _make_key(args, kwargs, typed)

            # Get from cache
            try:
                return cache[key]
            except KeyError:
                pass

            # Miss, retrieve from coroutine
            value = yield from func(*args, **kwargs)
            cache[key] = value
            return value

        wrapper.cache = cache
        wrapper.cache_info = cache.info
        wrapper.cache_clear = cache.clear

        return functools.update_wrapper(wrapper, func)

    return decorating_function
