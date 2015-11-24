"""
Provides classes and functions for the end-to-end encryption mode.
"""
import abc
import enum
import random
import binascii
import struct
import mimetypes

import libnacl
import libnacl.public
import libnacl.encode

from threema.gateway import ReceptionCapability
from threema.gateway.exception import *
from threema.gateway.key import Key

__all__ = (
    'encrypt',
    'decrypt',
    'encrypt_raw',
    'decrypt_raw',
    'Message',
    'DeliveryReceipt',
    'TextMessage',
    'ImageMessage',
)


def encrypt(private, public, data):
    """
    Encrypt a message.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `data`: Message data (bytes).

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Generate 0 < padding < 256
    padding_length = random.randint(1, 255)

    # Add padding to the payload
    padding = bytes([padding_length] * padding_length)

    # Assemble and encrypt the payload
    return encrypt_raw(private, public, data + padding)


def decrypt(private, public, nonce, data):
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
    # Decrypt payload
    payload = decrypt_raw(private, public, nonce, data)

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


def encrypt_raw(private, public, data):
    """
    Encrypt data.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `image`: Data (bytes).

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Assemble and encrypt the payload
    box = libnacl.public.Box(sk=private, pk=public)
    return box.encrypt(data, pack_nonce=False)


def decrypt_raw(private, public, nonce, data):
    """
    Decrypt data.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted data (bytes).

    Return the decrypted data.
    """
    # Decrypt payload
    box = libnacl.public.Box(sk=private, pk=public)
    return box.decrypt(data, nonce)


class Message(metaclass=abc.ABCMeta):
    """
    A message class all end-to-end mode messages are derived from.

    Attributes:
        - `type_`: The message type.
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
    def __init__(self, type_, connection=None, id=None, key=None, key_file=None):
        self._key = None
        self._key_file = None
        self.connection = connection
        self.type = type_
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

    def _encrypt(self, message, private=None, public=None):
        """
        Encrypt a message.

        Arguments:
            - `message`: Message data (bytes).
            - `private`: Private key of the sender.
            - `public`: The public key of the recipient.

        Return a tuple of bytes containing the nonce and the encrypted
        data.
        """
        # Keys specified?
        if private is None and public is None:
            private = self.connection.key
            public = self.key

        # Encrypt
        return encrypt(private, public, message)

    def _decrypt(self, nonce, data, private=None, public=None):
        """
        Decrypt a message.

        Arguments:
            - `nonce`: The nonce of the encrypted message.
            - `data`: Encrypted message (bytes).
            - `private`: Private key of the sender.
            - `public`: The public key of the recipient.

        Return a tuple of the nonce and the encrypted data.
        """
        # Keys specified?
        if private is None and public is None:
            private = self.connection.key
            public = self.key

        # Decrypt
        return decrypt(private, public, nonce, data)

    def _encrypt_raw(self, data, private=None, public=None):
        """
        Encrypt data.

        Arguments:
            - `data`: Data (bytes).
            - `private`: Private key of the sender.
            - `public`: The public key of the recipient.

        Return a tuple of bytes containing the nonce and the encrypted
        data.
        """
        # Keys specified?
        if private is None and public is None:
            private = self.connection.key
            public = self.key

        # Encrypt
        return encrypt_raw(private, public, data)

    def _decrypt_raw(self, nonce, data, private=None, public=None):
        """
        Decrypt data.

        Arguments:
            - `nonce`: The nonce of the encrypted message.
            - `data`: Encrypted data (bytes).
            - `private`: Private key of the sender.
            - `public`: The public key of the recipient.

        Return a tuple of the nonce and the encrypted data.
        """
        # Keys specified?
        if private is None and public is None:
            private = self.connection.key
            public = self.key

        # Decrypt
        return decrypt_raw(private, public, nonce, data)

    def _check_capabilities(self, required_capabilities):
        """
        Test for capabilities of a recipient.

        Arguments:
            - `required_capabilities`: A set of capabilities that are
              required.

        Raise :class:`MissingCapabilityError` in case that one or more
        capabilities are missing.
        """
        # Check capabilities of a recipient
        recipient_capabilities = self.connection.get_reception_capabilities(self.id)
        if not required_capabilities <= recipient_capabilities:
            missing_capabilities = required_capabilities - recipient_capabilities
            raise MissingCapabilityError(missing_capabilities)


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
    class ReceiptType(enum.Enum):
        """Describes message receipt types."""
        received = b'\x01'
        read = b'\x02'
        user_ack = b'\x03'

    def __init__(self, payload):
        super().__init__(Message.Type.delivery_receipt)

        # Check length
        if len(payload) < 9 or (len(payload) - 1) % 8 != 0:
            raise MessageError('Invalid delivery receipt length')

        # Unpack payload
        type_, *self.ids = struct.unpack('1s' + '8s' * int(len(payload) / 8), payload)
        self.receipt_type = self.ReceiptType(type_)

    def __str__(self):
        ids = (binascii.hexlify(id_).decode('utf-8') for id_ in self.ids)
        return 'Delivery receipt({}): {}'.format(self.receipt_type.name, ', '.join(ids))

    def send(self):
        """
        Send a delivery receipt.
        """
        raise NotImplementedError(
            'Creating and sending delivery receipts is currently not supported')


class TextMessage(Message):
    """
    A text message.

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
        super().__init__(Message.Type.text_message, **kwargs)

        # Validate arguments
        mode = [argument for argument in (text, payload) if argument is not None]
        if len(mode) != 1:
            raise MessageError("Either 'text' or 'payload' need to be specified.")

        # Unpack payload or store text
        if payload is not None:
            self.text = payload.decode('utf-8')
        else:
            self.text = text

    def __str__(self):
        return self.text

    def encrypt(self, *args, **kwargs):
        """
        Encrypt the text message.

        Arguments:
            - `private`: The private key of the sender. Only
              required when there is no :class:`Connection` instance.
            - `public`: The public key of the recipient. Only
              required when there is no :class:`Connection` instance.

        Return a tuple of the nonce and the encrypted message.
        """
        # Pack payload
        text = self.text.encode('utf-8')
        data = self.type.value + text

        # Encrypt
        return self._encrypt(data, *args, **kwargs)

    def send(self):
        """
        Send the encrypted text message.

        Return the ID of the message.
        """
        # Encrypt
        nonce, message = self.encrypt()

        # Send message
        return self.connection.send_e2e(**{
            'to': self.id,
            'nonce': binascii.hexlify(nonce),
            'box': binascii.hexlify(message)
        })


class ImageMessage(Message):
    """
    An image message including a thumbnail.

    Arguments for a new message:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `key`: The public key of the recipient. Will be fetched from
           the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
        - `image_path`: A file where the image is stored in.

    Arguments for an existing message:
        - `payload`: The remaining byte sequence of a decrypted
          message.
    """
    allowed_mime_types = {
        'image/jpg',
        'image/jpeg',
        'image/png'
    }

    required_capabilities = {
        ReceptionCapability.image
    }

    def __init__(self, image_path=None, payload=None, **kwargs):
        super().__init__(Message.Type.image_message, **kwargs)

        # Validate arguments
        mode = [argument for argument in (image_path, payload) if argument is not None]
        if len(mode) != 1:
            raise MessageError("Either 'image_path' or 'payload' need to be specified.")

        # Unpack payload or store image path
        if payload is not None:
            self.image = payload
            self.image_path = None
            # TODO: Download image, decode thumbnail, set and validate mime type
            raise NotImplementedError()
        else:
            self.image = None
            self.image_path = image_path

            # Guess the mime type
            mime_type, _ = mimetypes.guess_type(image_path)
            if mime_type not in self.allowed_mime_types:
                raise UnsupportedMimeTypeError(mime_type)
            self.mime_type = mime_type

    def send(self):
        """
        Send the encrypted image message.

        Return the ID of the message.
        """
        # Check capabilities of recipient
        self._check_capabilities(self.required_capabilities)

        # Read the content of the file if not already read
        if self.image is None:
            with open(self.image_path, mode='rb') as file:
                self.image = file.read()

        # Encrypt and upload image
        image_nonce, image_data = self._encrypt_raw(self.image)
        blob_id = binascii.unhexlify(self.connection.upload(image_data))

        # Pack payload
        data = struct.pack(
            '<1s{}sI{}s'.format(len(blob_id), len(image_nonce)),
            self.type.value, blob_id, len(image_data), image_nonce
        )

        # Encrypt
        nonce, message = self._encrypt(data)

        # Send message
        return self.connection.send_e2e(**{
            'to': self.id,
            'nonce': binascii.hexlify(nonce),
            'box': binascii.hexlify(message)
        })
