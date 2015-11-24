"""
Utility functions.
"""
from threema.gateway.key import Key

__all__ = (
    'read_key_or_key_file',
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
