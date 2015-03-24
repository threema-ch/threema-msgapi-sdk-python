"""
Utility functions.
"""
from threema.gateway.key import Key

__all__ = ('read_key_or_key_file',)


def read_key_or_key_file(key, expected_type):
    # Read key file (if any)
    try:
        with open(key) as file:
            key = file.readline().strip()
    except IOError:
        pass

    # Convert to key instance
    return Key.decode(key, expected_type)
