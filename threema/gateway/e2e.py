"""
Provides classes and functions for the end-to-end encryption mode.
"""
import abc
import enum
import os
import binascii
import struct
import mimetypes
import json
import asyncio

import libnacl
import libnacl.public
import libnacl.secret
import libnacl.encode

from . import ReceptionCapability, util
from .exception import *
from .key import Key

__all__ = (
    'encrypt',
    'decrypt',
    'Message',
    'DeliveryReceipt',
    'TextMessage',
    'ImageMessage',
    'FileMessage',
)


def encrypt(private, public, data, nonce=None):
    """
    Encrypt a message by using public-key encryption.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `data`: Message data (bytes).
        - `nonce`: A predefined nonce.

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Generate 0 < padding < 256
    padding_length = util.randint(1, 255)

    # Add padding to the payload
    padding = bytes([padding_length] * padding_length)

    # Assemble and encrypt the payload
    return pk_encrypt_raw(private, public, data + padding, nonce=nonce)


def decrypt(private, public, nonce, data):
    """
    Decrypt a message by using public-key decryption.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted message (bytes).

    Return an instance of either a :class:`DeliveryReceipt` or a
    :class:`TextMessage`.
    """
    # Decrypt payload
    payload = pk_decrypt_raw(private, public, nonce, data)

    # Remove padding and type
    type_ = payload[:1]
    padding_length = int.from_bytes(payload[-1:], byteorder='little')
    payload = payload[1:-padding_length]

    # Extract message or delivery receipt
    type_ = Message.Type(type_)
    if type_ == Message.Type.text_message:
        return TextMessage(payload=payload)
    elif type_ == Message.Type.group_text_message:
        return TextMessage(payload=payload, group=True)
    elif type_ == Message.Type.delivery_receipt:
        return DeliveryReceipt(payload=payload)


def pk_encrypt_raw(private, public, data, nonce=None):
    """
    Encrypt data by using public-key encryption.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `data`: Data (bytes).
        - `nonce`: A predefined nonce.

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Assemble and encrypt the payload
    box = libnacl.public.Box(sk=private, pk=public)
    return box.encrypt(data, nonce=nonce, pack_nonce=False)


def pk_decrypt_raw(private, public, nonce, data):
    """
    Decrypt data by using public-key decryption.

    Arguments:
        - `private`: Private key of the sender.
        - `public`: The public key of the recipient.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted data (bytes).

    Return the decrypted data.
    """
    # Decrypt payload
    box = libnacl.public.Box(sk=private, pk=public)
    return box.decrypt(data, nonce=nonce)


def sk_encrypt_raw(key, data, nonce=None):
    """
    Encrypt data by using secret-key encryption.

    Arguments:
        - `key`: The secret key.
        - `data`: Data (bytes).
        - `nonce`: A predefined nonce.

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Assemble and encrypt the payload
    box = libnacl.secret.SecretBox(key=key)
    # Note: Workaround for libnacl which lacks `pack_nonce` option
    # (see: https://github.com/saltstack/libnacl/pull/61)
    # return box.encrypt(data, nonce=nonce, pack_nonce=False)
    data = box.encrypt(data, nonce=nonce)
    nonce_length = libnacl.crypto_secretbox_NONCEBYTES
    return data[:nonce_length], data[nonce_length:]


def sk_decrypt_raw(key, nonce, data):
    """
    Decrypt data by using secret-key decryption.

    Arguments:
        - `key`: The secret key.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted data (bytes).

    Return the decrypted data.
    """
    # Decrypt payload
    box = libnacl.secret.SecretBox(key=key)
    return box.decrypt(data, nonce=nonce)


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
    nonce = {
        'file': (b'\x00' * 23) + b'\x01',
        'thumbnail': (b'\x00' * 23) + b'\x02'
    }

    @enum.unique
    class Type(enum.Enum):
        """
        The type of a message.
        """
        text_message = b'\x01'
        image_message = b'\x02'
        file_message = b'\x17'
        delivery_receipt = b'\x80'

        """
        Group Message Types
        """
        group_text_message = b'A'
        group_update = b'K'
        group_closed = b'L'
        group_invitation = b'J'

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
    @asyncio.coroutine
    def key(self):
        """
        Get the public key of the recipient. Will be request from the
        server if necessary. Note that the getter is a coroutine!

        Set the public key of the recipient. The key will be decoded
        if required.
        """
        if self._key is None:
            self._key = yield from self.connection.get_public_key(self.id)
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

    @asyncio.coroutine
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
            public = yield from self.key

        # Encrypt
        return encrypt(private, public, message)

    @asyncio.coroutine
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
            public = yield from self.key

        # Decrypt
        return decrypt(private, public, nonce, data)

    @asyncio.coroutine
    def _pk_encrypt_raw(self, data, private=None, public=None):
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
            public = yield from self.key

        # Encrypt
        return pk_encrypt_raw(private, public, data)

    @asyncio.coroutine
    def _pk_decrypt_raw(self, nonce, data, private=None, public=None):
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
            public = yield from self.key

        # Decrypt
        return pk_decrypt_raw(private, public, nonce, data)

    @asyncio.coroutine
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
        capabilities_coroutine = self.connection.get_reception_capabilities(self.id)
        recipient_capabilities = yield from capabilities_coroutine
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
    def __init__(self, text=None, payload=None, group=None, **kwargs):
        super().__init__(Message.Type.text_message, **kwargs)

        # Validate arguments
        mode = [argument for argument in (text, payload) if argument is not None]
        if len(mode) != 1:
            raise MessageError("Either 'text' or 'payload' need to be specified.")

        # Unpack payload or store text
        if payload is not None and group is None:
            self.text =  payload.decode('utf-8')
        elif payload is not None and group is True:
            self.text = payload[16:].decode('utf-8')
        else:
            self.text = text

    def __str__(self):
        return self.text

    @asyncio.coroutine
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
        return (yield from self._encrypt(data, *args, **kwargs))

    @asyncio.coroutine
    def send(self):
        """
        Send the encrypted text message.

        Return the ID of the message.
        """
        # Encrypt
        nonce, message = yield from self.encrypt()

        # Send message
        return (yield from self.connection.send_e2e(**{
            'to': self.id,
            'nonce': binascii.hexlify(nonce).decode(),
            'box': binascii.hexlify(message).decode()
        }))


class ImageMessage(Message):
    """
    An image message.

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

    @asyncio.coroutine
    def send(self):
        """
        Send the encrypted image message.

        Return the ID of the message.
        """
        # Check capabilities of recipient
        yield from self._check_capabilities(self.required_capabilities)

        # Read the content of the file if not already read
        if self.image is None:
            try:
                with open(self.image_path, mode='rb') as file:
                    self.image = file.read()
            except OSError as exc:
                raise MessageError('Fetching content of image failed') from exc

        # Encrypt and upload image
        image_nonce, image_data = yield from self._pk_encrypt_raw(self.image)
        blob_id = binascii.unhexlify((yield from self.connection.upload(image_data)))

        # Pack payload
        data = struct.pack(
            '<1s{}sI{}s'.format(len(blob_id), len(image_nonce)),
            self.type.value, blob_id, len(image_data), image_nonce
        )

        # Encrypt
        nonce, message = yield from self._encrypt(data)

        # Send message
        return (yield from self.connection.send_e2e(**{
            'to': self.id,
            'nonce': binascii.hexlify(nonce).decode(),
            'box': binascii.hexlify(message).decode()
        }))


class FileMessage(Message):
    """
    A file message including a thumbnail.

    Arguments for a new message:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `key`: The public key of the recipient. Will be fetched from
           the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
        - `file_path`: The path to a file.
        - `thumbnail_path`: The path to a thumbnail of the file.

    Arguments for an existing message:
        - `payload`: The remaining byte sequence of a decrypted
          message.
    """
    required_capabilities = {
        ReceptionCapability.file
    }

    def __init__(self, file_path=None, thumbnail_path=None, payload=None, **kwargs):
        super().__init__(Message.Type.file_message, **kwargs)

        # Validate arguments
        mode = [argument for argument in (file_path, payload) if argument is not None]
        if len(mode) != 1:
            raise MessageError("Either 'file_path' or 'payload' need to be specified.")

        # Unpack payload or store file path
        if payload is not None:
            self.file_content = payload
            self.file_path = None
            self.thumbnail_content = None
            self.thumbnail_path = None
            # TODO: Download file, decode thumbnail
            raise NotImplementedError()
        else:
            self.file_content = None
            self.file_path = file_path
            self.thumbnail_content = None
            self.thumbnail_path = thumbnail_path

            # Guess the mime type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                # Fallback mime type
                mime_type = 'application/octet-stream'
            self.mime_type = mime_type

            # TODO: Check the mime type of the thumbnail?

    @asyncio.coroutine
    def send(self):
        """
        Send the encrypted file message.

        Return the ID of the message.
        """
        # Check capabilities of recipient
        yield from self._check_capabilities(self.required_capabilities)

        # Read the content of the file if not already read
        if self.file_content is None:
            try:
                with open(self.file_path, mode='rb') as file:
                    self.file_content = file.read()
            except OSError as exc:
                raise MessageError('Fetching content of file failed') from exc

        # Create symmetric key
        key, hex_key = Key.generate_secret_key()

        # Encrypt and upload file
        _, file_data = sk_encrypt_raw(key, self.file_content, nonce=self.nonce['file'])
        file_id = yield from self.connection.upload(file_data)

        # Build JSON
        content = {
            'b': file_id,
            'k': hex_key.decode('utf-8'),
            'm': self.mime_type,
            'n': os.path.basename(self.file_path),
            's': len(self.file_content),
            'i': 0,
        }

        # Encrypt and upload thumbnail (if any)
        if self.thumbnail_path is not None:
            # Read the content of the thumbnail file if not already read
            if self.thumbnail_content is None:
                try:
                    with open(self.thumbnail_path, mode='rb') as file:
                        self.thumbnail_content = file.read()
                except OSError as exc:
                    raise MessageError('Fetching content of thumbnail failed') from exc

            # Encrypt and upload thumbnail
            _, thumbnail_data = sk_encrypt_raw(key, self.thumbnail_content,
                                               nonce=self.nonce['thumbnail'])
            thumbnail_id = yield from self.connection.upload(thumbnail_data)

            # Update JSON
            content['t'] = thumbnail_id

        # Pack payload (compact JSON encoding)
        content = json.dumps(content, separators=(',', ':')).encode('utf-8')
        data = self.type.value + content

        # Encrypt
        nonce, message = yield from self._encrypt(data)

        # Send message
        return (yield from self.connection.send_e2e(**{
            'to': self.id,
            'nonce': binascii.hexlify(nonce).decode(),
            'box': binascii.hexlify(message).decode()
        }))
