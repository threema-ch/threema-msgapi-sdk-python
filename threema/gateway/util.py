"""
Utility functions.
"""
import asyncio
import io
import os

import libnacl

from .key import Key

__all__ = (
    'read_key_or_key_file',
    'raise_server_error',
    'randint',
    'ViewIOReader',
    'ViewIOWriter',
)


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
