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

.. moduleauthor:: Lennart Grahl <lennart.grahl@gmail.com>
"""
import itertools

from . import _gateway
from . import exception as _exception
from ._gateway import *  # noqa
from .exception import *  # noqa

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Production'
__version__ = '4.0.0'
feature_level = 3

__all__ = tuple(itertools.chain(
    ('feature_level',),
    ('bin', 'simple', 'e2e', 'key', 'util'),
    _gateway.__all__,
    _exception.__all__,
))
