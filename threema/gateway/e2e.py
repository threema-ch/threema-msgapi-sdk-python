"""
Provides classes and functions for the end-to-end encryption mode.
"""
import abc
import enum
import random
import binascii
import struct

import libnacl
import libnacl.public
import libnacl.encode

from threema.gateway import MessageError
from threema.gateway.key import Key

__all__ = ('encrypt', 'decrypt', 'Message', 'DeliveryReceipt', 'TextMessage')


def encrypt(private, public, data):
    """
    Encrypt a message.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `data`: Message data (bytes).

    Return a tuple of the nonce and the encrypted message. Both
    values are hex-encoded.
    """
    # Generate 0 < padding < 256
    padding_length = random.randint(1, 255)

    # Add padding to the payload
    padding = bytes([padding_length] * padding_length)

    # Assemble and encrypt the payload
    box = libnacl.public.Box(sk=private, pk=public)
    nonce, message = box.encrypt(data + padding, pack_nonce=False)

    # Return as hex
    return binascii.hexlify(nonce), binascii.hexlify(message)


def decrypt(private, public, nonce, message):
    """
    Decrypt a message.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted message (bytes).

    Return an instance of either a :class:`DeliveryReceipt` or a
    :class:`TextMessage`.
    """
    # Un-hexlify
    nonce, message = binascii.unhexlify(nonce), binascii.unhexlify(message)

    # Decrypt payload
    box = libnacl.public.Box(sk=private, pk=public)
    payload = box.decrypt(message, nonce)

    # Remove padding and type
    type_ = payload[:1]
    padding_length = int.from_bytes(payload[-1:], byteorder='little')
    payload = payload[1:-padding_length]

    # Extract message or delivery receipt
    type_ = Message.Type(type_)
    if type_ == Message.Type.text_message:
        return TextMessage(payload=payload)
    elif type_ == Message.Type.delivery_receipt:
        return DeliveryReceipt(payload=payload)


class Message(metaclass=abc.ABCMeta):
    """
    A message class all end-to-end mode messages are derived from.

    Attributes:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `key`: The public key of the recipient. Will be fetched from
           the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
    """

    @enum.unique
    class Type(enum.Enum):
        """
        The type of a message.
        """
        text_message = b'\x01'
        image_message = b'\x02'
        file_message = b'\x17'
        delivery_receipt = b'\x80'

    # noinspection PyShadowingBuiltins
    def __init__(self, connection=None, id=None, key=None, key_file=None):
        self._key = None
        self._key_file = None
        self.connection = connection
        self.id = id
        self.key = key
        self.key_file = key_file

    @property
    def key(self):
        """
        Get the public key of the recipient. Will be request from the
        server if necessary.

        Set the public key of the recipient. The key will be decoded
        if required.
        """
        if self._key is None:
            self._key = self.connection.get_public_key(self.id)
        return self._key

    @key.setter
    def key(self, key):
        if isinstance(key, str):
            key = Key.decode(key, Key.Type.public)
        self._key = key

    @property
    def key_file(self):
        """
        Get the path of the recipients public key file.

        Set the public key of the recipient by reading it from a file.
        """
        return self._key_file

    @key_file.setter
    def key_file(self, key_file):
        if key_file is not None:
            with open(key_file) as file:
                self.key = file.readline().strip()
        self._key_file = key_file

    @abc.abstractmethod
    def send(self):
        """
        Send a message.
        """


class DeliveryReceipt(Message):
    """
    A delivery receipt that can be sent or received in end-to-end
    mode. Each delivery receipt message confirms the receipt of one
    or multiple regular text messages.

    .. note:: Creating and sending delivery receipts is currently not
              supported.

    Arguments:
        - `payload`: The remaining byte sequence of the message.
    """

    @enum.unique
    class Type(enum.Enum):
        """Describes message receipt types."""
        received = b'\x01'
        read = b'\x02'
        user_ack = b'\x03'

    def __init__(self, payload):
        super(DeliveryReceipt, self).__init__()

        # Check length
        if len(payload) < 9 or (len(payload) - 1) % 8 != 0:
            raise MessageError('Invalid delivery receipt length')

        # Unpack payload
        type_, *self.ids = struct.unpack('1s' + '8s' * int(len(payload) / 8), payload)
        self.type = self.Type(type_)

    def __str__(self):
        ids = (binascii.hexlify(id_).decode('utf-8') for id_ in self.ids)
        return 'Delivery receipt({}): {}'.format(self.type.name, ', '.join(ids))

    def send(self):
        """
        Send a delivery receipt.
        """
        raise NotImplementedError()


class TextMessage(Message):
    """
    A simple text message.

    Arguments for a new message:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `key`: The public key of the recipient. Will be fetched from
           the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
        - `text`: Message text. Will be encrypted automatically.

    Arguments for an existing message:
        - `payload`: The remaining byte sequence of a decrypted
          message.
    """
    def __init__(self, text=None, payload=None, **kwargs):
        super(TextMessage, self).__init__(**kwargs)

        # Validate arguments
        mode = [argument for argument in (text, payload) if argument is not None]
        if len(mode) != 1:
            raise MessageError("Either 'text' or 'payload' need to be specified.")

        # Unpack payload or store text
        if payload is not None:
            self.text = str(payload, encoding='utf-8')
        else:
            self.text = text

    def __str__(self):
        return self.text

    def encrypt(self, private_key=None, public_key=None):
        """
        Encrypt the text message.

        Arguments:
            - `private_key`: The private key of the sender. Only
              required when there is no :class:`Connection` instance.
            - `public_key`: The public key of the recipient. Only
              required when there is no :class:`Connection` instance.

        Return a tuple of the nonce and the encrypted message.
        """
        # Pack payload
        type_ = Message.Type.text_message.value
        text = bytes(self.text, encoding='utf-8')
        data = type_ + text

        # Keys specified?
        if private_key is None and public_key is None:
            private_key = self.connection.key
            public_key = self.key

        # Encrypt
        return encrypt(private_key, public_key, data)

    def send(self):
        """
        Send the encrypted text message.

        Return the ID of the message.
        """
        # Validate parameters
        if self.connection is None:
            raise MessageError('No connection set')
        if self.id is None:
            raise MessageError('No recipient specified')
        if self.text is None:
            raise MessageError('Message text not specified')

        # Encrypt
        nonce, message = self.encrypt()

        # Send message
        return self.connection.send_e2e(**{
            'to': self.id,
            'nonce': nonce,
            'box': message
        })
