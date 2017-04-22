"""
Provides classes for the simple mode.
"""
import abc
import asyncio

from .exception import MessageError
from .util import (
    AioRunMixin,
    aio_run_proxy_decorator,
)

__all__ = (
    'Message',
    'TextMessage',
)


class Message(AioRunMixin, metaclass=abc.ABCMeta):
    """
    A message class all simple mode messages are derived from.

    Attributes:
        - `connection`: An instance of a connection.
        - `to_id`: Threema ID of the recipient.
    """
    async_functions = {
        'send',
    }

    def __init__(self, connection=None, to_id=None):
        super().__init__(blocking=connection.blocking)
        self._connection = connection.unwrap
        self.to_id = to_id

    @asyncio.coroutine
    @abc.abstractmethod
    def send(self):
        """
        Send a message.
        """


@aio_run_proxy_decorator
class TextMessage(Message):
    """
    Create and send a text message to a recipient.

    Arguments / Attributes:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `phone`: Phone number of the recipient.
        - `email`: Email address of the recipient.
        - `text`: Message text.
    """
    async_functions = {
        'send',
    }

    def __init__(self, phone=None, email=None, text=None, **kwargs):
        super().__init__(**kwargs)
        self.phone = phone
        self.email = email
        self.text = text

    @asyncio.coroutine
    def send(self):
        """
        Send the created message.

        Return the ID of the sent message.
        """
        recipient = {
            'to': self.to_id,
            'phone': self.phone,
            'email': self.email
        }

        # Validate parameters
        if self._connection is None:
            raise MessageError('No connection set')
        if not any(recipient.values()):
            raise MessageError('No recipient specified')
        if sum([0 if to is None else 1 for to in recipient.values()]) > 1:
            raise MessageError('Only one recipient type can be used at the same time')
        if self.text is None:
            raise MessageError('Message text not specified')

        # Send message
        data = {key: value for key, value in recipient.items() if value is not None}
        data['text'] = self.text
        return (yield from self._connection.send_simple(**data))
