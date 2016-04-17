"""
Utility functions.
"""
import asyncio
import io
import os

import libnacl
import logging
import logbook
import logbook.compat
import logbook.more

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
