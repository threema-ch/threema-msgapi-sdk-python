"""
This API can be used to send text messages to any Threema user, and to
receive incoming messages and delivery receipts.

There are two main modes of operation:

* Basic mode (server-based encryption)
    - The server handles all encryption for you.
    - The server needs to know the private key associated with your
      Threema API identity.
    - Incoming messages and delivery receipts are not supported.

* End-to-end encrypted mode
    - The server doesn't know your private key.
    - Incoming messages and delivery receipts are supported.
    - You need to run software on your side to encrypt each message
      before it can be sent, and to decrypt any incoming messages or
      delivery receipts.

The mode that you can use depends on the way your account was set up.

.. moduleauthor:: Lennart Grahl <lennart.grahl@threema.ch>
"""
import itertools

from ._gateway import *
from ._gateway import __version__
from .exception import *
from . import bin, simple, e2e, key, util

__all__ = tuple(itertools.chain(
    _gateway.__all__,
    exception.__all__,
    ('bin', 'simple', 'e2e', 'key', 'util')
))
