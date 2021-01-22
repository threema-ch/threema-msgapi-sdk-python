"""
Provides classes and functions for the end-to-end encryption mode.
"""
import abc
import binascii
import collections
import datetime
import enum
import functools
import hashlib
import hmac
import json
import mimetypes
import os
import struct
from typing import Tuple

import libnacl
import libnacl.encode
import libnacl.public
import libnacl.secret
from aiohttp import web

from . import ReceptionCapability
from .exception import (
    CallbackError,
    DirectionError,
    MessageError,
    MissingCapabilityError,
    UnsupportedMimeTypeError,
)
from .key import Key
from .util import (
    AioRunMixin,
    ViewIOReader,
    ViewIOWriter,
    aio_run_proxy,
    randint,
)

__all__ = (
    'BLOB_ID_LENGTH',
    'MAX_HTTP_REQUEST_SIZE',
    'CallbackContext',
    'handle_callback',
    'create_application',
    'add_callback_route',
    'Message',
    'DeliveryReceipt',
    'TextMessage',
    'ImageMessage',
    'VideoMessage',
    'FileMessage',
)

BLOB_ID_LENGTH = 16

# A box can contain up to 4000 bytes, so this should be sufficient.
# The remaining POST parameters aren't that big.
# See: https://gateway.threema.ch/en/developer/api
MAX_HTTP_REQUEST_SIZE = 8192


def _pk_encrypt(key_pair: Tuple[Key, Key], data: bytes, nonce: bytes = None):
    """
    Encrypt data by using public-key encryption.

    Arguments:
        - `key_pair`: A tuple containing our private key and the public
          key of the recipient.
        - `data`: Raw data.
        - `nonce`: A predefined nonce.

    Raises `libnacl.CryptError` in case the data could not be encrypted.
    Raises `ValueError` in other cases.

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Assemble and encrypt the payload
    private, public = key_pair
    box = libnacl.public.Box(sk=private, pk=public)
    return box.encrypt(data, nonce=nonce, pack_nonce=False)


def _pk_decrypt(key_pair: Tuple[Key, Key], nonce: bytes, data: bytes):
    """
    Decrypt data by using public-key decryption.

    Arguments:
        - `key_pair`: A tuple containing our private key and the public
          key of the sender.
        - `nonce`: The nonce of the encrypted data.
        - `data`: Encrypted data.

    Raises `libnacl.CryptError` in case the data could not be decrypted.
    Raises `ValueError` in other cases.

    Return the decrypted data.
    """
    # Decrypt payload
    private, public = key_pair
    box = libnacl.public.Box(sk=private, pk=public)
    return box.decrypt(data, nonce=nonce)


def _sk_encrypt(key, data, nonce=None):
    """
    Encrypt data by using secret-key encryption.

    Arguments:
        - `key`: A secret key.
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


def _sk_decrypt(key, nonce, data):
    """
    Decrypt data by using secret-key decryption.

    Arguments:
        - `key`: A secret key.
        - `nonce`: The nonce of the encrypted message.
        - `data`: Encrypted data (bytes).

    Return the decrypted data.
    """
    # Decrypt payload
    box = libnacl.secret.SecretBox(key=key)
    return box.decrypt(data, nonce=nonce)


def _validate_hmac(encoded_secret, expected_mac, response):
    try:
        message = ''.join((
            response['from'],
            response['to'],
            response['messageId'],
            response['date'],
            response['nonce'],
            response['box'],
        )).encode('ascii')
    except UnicodeError as exc:
        raise CallbackError(400, 'Cannot concatenate HMAC message') from exc
    hmac_ = hmac.new(encoded_secret, msg=message, digestmod=hashlib.sha256)
    actual_mac = hmac_.hexdigest()
    if not hmac.compare_digest(expected_mac, actual_mac):
        raise CallbackError(400, 'MACs do not match')


CallbackContext = collections.namedtuple('CallbackContext', [
    'encoded_secret', 'connection', 'message_handler', 'receive_handler',
])


async def handle_callback(context, request):
    try:
        response = await request.post()

        # Unpack fields
        try:
            from_id = response['from']
            to_id = response['to']
            message_id = response['messageId']
            date = response['date']
            nonce = response['nonce']
            data = response['box']
            mac = response['mac']
        except KeyError as exc:
            raise CallbackError(400, 'Could not unpack required fields') from exc

        # Validate HMAC and ID
        _validate_hmac(context.encoded_secret, mac, response)
        if to_id != context.connection.id:
            raise CallbackError(400, 'IDs do not match')

        # Validate from id length
        if len(from_id) != 8:
            raise CallbackError(400, "Invalid 'from' value")

        # Convert date and message id
        try:
            message_id = binascii.unhexlify(message_id)
        except binascii.Error as exc:
            raise CallbackError(400, 'Invalid message ID') from exc
        try:
            date = datetime.datetime.fromtimestamp(float(date))
        except (ValueError, TypeError) as exc:
            raise CallbackError(400, 'Invalid date') from exc

        # Convert nonce and data
        try:
            nonce = binascii.unhexlify(nonce)
            data = binascii.unhexlify(data)
        except binascii.Error as exc:
            raise CallbackError(400, 'Invalid nonce or data') from exc

        # Unpack message
        try:
            message = await context.receive_handler(context.connection, {
                'from_id': from_id,
                'message_id': message_id,
                'date': date,
            }, nonce, data)
        except MessageError as exc:
            raise CallbackError(400, str(exc)) from exc

        # Pass message to handler
        await context.message_handler(message)

        # Respond with 'OK'
        return web.Response(status=200)
    except CallbackError as exc:
        # Note: For security reasons, we do not send the reason
        return web.Response(status=exc.status)
    except Exception:
        raise


def create_application(connection):
    application = web.Application(client_max_size=MAX_HTTP_REQUEST_SIZE)
    return application


def add_callback_route(
    connection, application, message_handler,
    path='/gateway_callback', receive_handler=None,
):
    if receive_handler is None:
        receive_handler = Message.receive
    context = CallbackContext(
        connection.secret.encode('ascii'),
        connection,
        message_handler,
        receive_handler,
    )
    application.router.add_routes([web.post(
        path, functools.partial(handle_callback, context))])


# TODO: Update docstring (arguments)
class Message(AioRunMixin, metaclass=abc.ABCMeta):
    """
    A message class all end-to-end mode messages are derived from.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

    Attributes:
        - `connection`: An instance of a connection.
        - `type_`: The message type.
        - `id_`: Threema ID of the sender (incoming) or recipient
          (outgoing).
        - `key`: The public key of the sender/recipient. Will be
          fetched from the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
    """
    async_functions = {
        'key',
        'send',
        'receive',
        'pack',
        'unpack',
        'check_capabilities',
        'get_encrypt_key_pair',
        'get_decrypt_key_pair',
        'encrypt',
    }
    nonce = {
        'video': (b'\x00' * 23) + b'\x01',
        'file': (b'\x00' * 23) + b'\x01',
        'thumbnail': (b'\x00' * 23) + b'\x02'
    }

    @enum.unique
    class Type(enum.IntEnum):
        """
        The type of a message.
        """
        text_message = 0x01
        image_message = 0x02
        video_message = 0x13
        file_message = 0x17
        delivery_receipt = 0x80

    @enum.unique
    class Direction(enum.IntEnum):
        """
        Incoming or outgoing message.
        """
        outgoing = 1
        incoming = 2

    @classmethod
    def get_message_class(cls, type_):
        """
        Return the corresponding :class:`Message` class for a
        :class:`Message.Type`.

        Arguments:
            - `type_`: A :class:`Message.Type`.

        Raises :exc:`KeyError` if no matching message class could be
        found.
        """
        if getattr(cls, '_message_classes', None) is None:
            cls._message_classes = {
                cls.Type.text_message: TextMessage,
                cls.Type.image_message: ImageMessage,
                cls.Type.video_message: VideoMessage,
                cls.Type.file_message: FileMessage,
                cls.Type.delivery_receipt: DeliveryReceipt,
            }
        return cls._message_classes[type_]

    def __init__(
            self, connection, type_,
            key=None, key_file=None,
            to_id=None, from_data=None
    ):
        super().__init__(blocking=connection.blocking)
        connection = connection.unwrap

        # Get direction
        if from_data is not None:
            direction = self.Direction.incoming
        else:
            direction = self.Direction.outgoing

        # Check required parameters
        if direction == self.Direction.outgoing:
            if to_id is None:
                message = "Parameter 'to_id' is required for outgoing messages."
                raise ValueError(message)
            from_id = connection.id
            message_id = date = None
        elif direction == self.Direction.incoming:
            keys = ('from_id', 'message_id', 'date')
            if any((key not in from_data for key in keys)):
                message = 'Parameters {} are required for incoming messages.'
                raise ValueError(message.format(keys))
            from_id = from_data['from_id']
            to_id = connection.id
            message_id = from_data['message_id']
            date = from_data['date']
        else:
            raise ValueError('Invalid direction value')

        # Required for both directions
        self._connection = connection
        self._direction = direction
        self._type = type_
        self._key = None
        self._key_file = None
        self.key = key
        self.key_file = key_file

        # Values depending on direction
        self.to_id = to_id  # Always set
        self.from_id = from_id  # Always set
        self.message_id = message_id  # None if outgoing
        self.date = date  # None if outgoing

    @property
    def type(self):
        """Return the :class:`Message.Type`."""
        return self._type

    # TODO: Raises?
    @property
    async def key(self):
        """
        Get the public key of the recipient (outgoing messages) or the
        sender (incoming messages). Will be request from the server
        if necessary. Note that the getter is a coroutine!

        Set the public key of the recipient or sender. The key will be
        decoded if required.
        """
        if self._key is None:
            self._key = await self._connection.get_public_key(self.to_id)
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

    # TODO: Raises?
    async def send(self, get_data_only=False):
        """
        Send a message.

        Raises :exc:`DirectionError` in case the message is not intended
        to be sent.
        """
        if self._direction != self.Direction.outgoing:
            raise DirectionError('Parameters are missing to send the message')
        writer = ViewIOWriter()

        # Pack type
        try:
            writer.writeexactly(struct.pack('<B', self.type.value))
        except struct.error as exc:
            raise MessageError('Could not pack type') from exc

        # Get content data
        await self.pack(writer)

        # Generate 0 < padding < 256
        padding_length = randint(1, 255)
        # Add padding to data
        writer.writeexactly(bytes([padding_length] * padding_length))

        # Encrypt message
        nonce, data = await self.encrypt(writer.getvalue())
        if get_data_only:
            return nonce, data

        # Send message
        return await self._connection.send_e2e(**{
            'to': self.to_id,
            'nonce': binascii.hexlify(nonce).decode('ascii'),
            'box': binascii.hexlify(data).decode('ascii')
        })

    # TODO: Raises?
    @classmethod
    async def receive(cls, connection, parameters, nonce, data):
        """
        Return a :class:`Message` instance from an encrypted message.

        The argument `parameters` contains the following items:
            - `from_id`: Sender's identity.
            - `message_id`: Message ID assigned by the sender as bytes.
            - `date`: A :class:´datetime.datetime` instance.

        Arguments:
            - `connection`: A :class:`Connection` instance.
            - `parameters`: A :class:`dict` containing parameters
              (see above).
            - `nonce`: A :class:`bytes`-like instance containing the
              messages' nonce.
            - `data`: A :class:`bytes`-like instance containing the
              encrypted message.

        Raises:
            - :exc:`MessageError` in case the message is invalid.
        """
        # Decrypt message
        key_pair = await cls.get_decrypt_key_pair(connection, parameters)
        data = cls.decrypt(nonce, data, key_pair)

        # Unpack type and padding length
        try:
            type_, *_ = struct.unpack('<B', data[:1])
            padding_length, *_ = struct.unpack('<B', data[-1:])
        except struct.error as exc:
            raise MessageError('Could not unpack type and padding') from exc

        # Validate type and get message class
        try:
            type_ = cls.Type(type_)
            class_ = cls.get_message_class(type_)
        except ValueError:
            raise MessageError('Cannot handle type: {}'.format(type_))

        # Remove type and padding from data
        reader = ViewIOReader(data[1:-padding_length])

        # Unpack message
        return await class_.unpack(connection, parameters, key_pair, reader)

    @abc.abstractmethod
    async def pack(self, writer):
        """
        Pack payload data.

        Arguments:
            - `writer`: A :class:`ViewIOWriter` instance to write data
              into.

        Raises `exc`:MessageError` in case the message could not be
        packed.
        """
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        """
        Return a :class:`Message` instance from raw payload data.

        The argument `parameters` contains the following items:
            - `from_id`: Sender's identity.
            - `message_id`: Message ID assigned by the sender as bytes.
            - `date`: A :class:´datetime.datetime` instance.

        Arguments:
            - `connection`: A :class:`Connection` instance.
            - `parameters`: A :class:`dict` containing parameters
              (see above).
            - `key_pair`: A tuple containing our private key and the
              public key of the sender.
            - `reader`: A :class:`ViewIOReader` containing the payload.

        Raises:
            - :exc:`MessageError` in case the message is invalid.
        """
        raise NotImplementedError

    # TODO: Raises?
    async def check_capabilities(self, required_capabilities):
        """
        Test for capabilities of a recipient.

        Arguments:
            - `required_capabilities`: A set of capabilities that are
              required.

        Raise :class:`MissingCapabilityError` in case that one or more
        capabilities are missing.
        """
        # Check capabilities of a recipient
        capabilities_coroutine = self._connection.get_reception_capabilities(self.to_id)
        recipient_capabilities = await capabilities_coroutine
        if not required_capabilities <= recipient_capabilities:
            missing_capabilities = required_capabilities - recipient_capabilities
            raise MissingCapabilityError(missing_capabilities)

    # TODO: Raises?
    @property
    async def get_encrypt_key_pair(self):
        """
        Return a tuple containing our private key and the public key of
        the recipient.
        """
        private = self._connection.key
        public = await self.key
        return private, public

    # TODO: Raises?
    @classmethod
    async def get_decrypt_key_pair(cls, connection, parameters):
        """
        Return a tuple containing our private key and the public key of
        the sender.

        Arguments:
            - `connection`: A :class:`Connection` instance.
            - `parameters`: Parameters passed to
              :method:`Message.unpack`.
        """
        private = connection.key
        public = await connection.get_public_key(parameters['from_id'])
        return private, public

    async def encrypt(self, data, key_pair=None, nonce=None):
        """
        Encrypt data.

        Arguments:
            - `data`: Raw data (bytes).
            - `key_pair`: A tuple containing our private key and the
              public key of the recipient.
            - A predefined nonce.

        Raises :exc:`MessageError` in case data could not be encrypted.

        Return a tuple of bytes containing the nonce and the encrypted
        data.
        """
        # Key pair specified?
        if key_pair is None:
            key_pair = await self.get_encrypt_key_pair

        # Encrypt
        try:
            return _pk_encrypt(key_pair, data, nonce=nonce)
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not encrypt data') from exc

    @classmethod
    def decrypt(cls, nonce, data, key_pair):
        """
        Decrypt data.

        Arguments:
            - `nonce`: The nonce of the encrypted data.
            - `data`: Encrypted data (bytes).
            - `key_pair`: A tuple containing our private key and the
              public key of the sender.

        Raises :exc:`MessageError` in case data could not be decrypted.

        Return decrypted data as :class:´bytes`.
        """
        # Decrypt
        try:
            return _pk_decrypt(key_pair, nonce, data)
        except (ValueError, libnacl.CryptError) as exc:
            raise MessageError('Could not decrypt data') from exc


# TODO: Update docstring (arguments)
@aio_run_proxy
class DeliveryReceipt(Message):
    """
    A delivery receipt that can be received in end-to-end mode.
    Each delivery receipt message confirms the receipt of one
    or multiple regular text messages.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

    Arguments:
        - `payload`: The remaining byte sequence of the message.
    """
    async_functions = {
        'pack',
        'unpack',
    }

    @enum.unique
    class ReceiptType(enum.IntEnum):
        """
        Describes message receipt types.
        """
        received = 0x01
        read = 0x02
        user_acknowledge = 0x03
        user_decline = 0x04

    def __init__(
            self, connection, receipt_type=None, message_ids=None,
            from_data=None, **kwargs
    ):
        super().__init__(connection, Message.Type.delivery_receipt,
                         from_data=from_data, **kwargs)
        if self._direction == self.Direction.outgoing:
            if receipt_type is None or message_ids is None:
                message = "Parameters 'receipt_type' and 'message_ids' are required"
                raise ValueError(message)
            self.receipt_type = receipt_type
            self.message_ids = message_ids
        else:
            self.receipt_type = from_data.get('receipt_type')
            self.message_ids = from_data.get('message_ids')

    def __str__(self):
        ids = (binascii.hexlify(id_).decode('ascii') for id_ in self.message_ids)
        return 'Delivery receipt({}): {}'.format(self.receipt_type.name, ', '.join(ids))

    async def pack(self, writer):
        # Pack content
        try:
            writer.writeexactly(struct.pack('<B', self.receipt_type.value))
        except struct.error as exc:
            raise MessageError('Could not pack receipt type') from exc
        for message_id in self.message_ids:
            writer.writeexactly(message_id)

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        # Check length
        length = len(reader)
        if length < 9 or (length - 1) % 8 != 0:
            raise MessageError('Invalid length')

        # Unpack content
        formatter = '<B' + '8s' * int((length - 1) // 8)
        data = reader.readexactly(length)
        try:
            receipt_type, *message_ids = struct.unpack(formatter, data)
        except struct.error as exc:
            message = 'Could not unpack receipt type and message ids'
            raise MessageError(message) from exc

        # Validate receipt type
        try:
            receipt_type = cls.ReceiptType(receipt_type)
        except ValueError as exc:
            raise MessageError('Unknown receipt type: {}'.format(receipt_type)) from exc

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'receipt_type': receipt_type,
            'message_ids': message_ids,
        }))


# TODO: Update docstring (arguments)
@aio_run_proxy
class TextMessage(Message):
    """
    A text message.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

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
    async_functions = {
        'pack',
        'unpack',
    }

    def __init__(self, connection, text=None, from_data=None, **kwargs):
        super().__init__(connection, Message.Type.text_message,
                         from_data=from_data, **kwargs)
        if self._direction == self.Direction.outgoing:
            if text is None:
                raise ValueError("Parameter 'text' required")
            self.text = text
        else:
            self.text = from_data.get('text')

    def __str__(self):
        return self.text

    async def pack(self, writer):
        # Encode text
        try:
            text = self.text.encode('utf-8')
        except UnicodeError as exc:
            raise MessageError('Could not encode text') from exc

        # Add text
        writer.writeexactly(text)

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        # Get text
        text = bytes(reader.readexactly(len(reader)))

        # Decode text
        try:
            text = text.decode('utf-8')
        except UnicodeError as exc:
            raise MessageError('Could not decode text') from exc

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'text': text,
        }))


# TODO: Update docstring (arguments)
@aio_run_proxy
class ImageMessage(Message):
    """
    An image message.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

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
    async_functions = {
        'pack',
        'unpack',
    }
    allowed_mime_types = {
        'image/jpg',
        'image/jpeg',
        'image/png'
    }
    required_capabilities = {
        ReceptionCapability.image
    }
    _formatter = '<{}sI{}s'.format(BLOB_ID_LENGTH, libnacl.crypto_box_NONCEBYTES)

    def __init__(
            self, connection,
            image=None, mime_type=None, image_path=None,
            from_data=None, **kwargs
    ):
        super().__init__(connection, Message.Type.image_message,
                         from_data=from_data, **kwargs)
        if self._direction == self.Direction.outgoing:
            image_and_mime = all((param is not None for param in [image, mime_type]))
            path_param = image_path is not None
            if sum((1 for param in (image_and_mime, path_param) if param)) != 1:
                raise ValueError(("Either 'image' and 'mime_type' or 'image_path' "
                                  "need to be specified"))
            self._image = image
            self._mime_type = mime_type
            self._image_path = image_path
        else:
            self._image = from_data['image']
            self._mime_type = from_data['mime_type']
            self._image_path = None

    @property
    def image(self):
        """
        Return the image as :class:`bytes`.

        Raises :exc:`OSError` in case the image could not be read from
        the specified path.
        """
        self._read_image()
        return self._image

    @property
    def mime_type(self):
        """
        Return the mime type as :class:`str`.
        """
        self._read_image()
        return self._mime_type

    def _read_image(self):
        """
        Read and store the image as :class:`bytes`.

        Raises :exc:`OSError` in case the image could not be read from
        the specified path.
        """
        if self._image is None:
            with open(self._image_path, mode='rb') as file:
                # Read content
                self._image = file.read()

            # Guess the mime type
            mime_type, _ = mimetypes.guess_type(self._image_path)
            if mime_type not in self.allowed_mime_types:
                raise UnsupportedMimeTypeError(mime_type)
            self._mime_type = mime_type

    async def pack(self, writer):
        # Check capabilities of recipient
        await self.check_capabilities(self.required_capabilities)

        # Encrypt and upload image
        image_nonce, image_data = await self.encrypt(self.image)
        blob_id = await self._connection.upload(image_data)
        try:
            blob_id = binascii.unhexlify(blob_id)
        except binascii.Error as exc:
            raise MessageError('Could not convert hex-encoded blob id') from exc

        # Pack blob id, image length and image nonce
        try:
            data = struct.pack(self._formatter, blob_id, len(self.image), image_nonce)
        except struct.error as exc:
            raise MessageError('Could not pack blob id, length and nonce') from exc

        # Add data
        writer.writeexactly(data)

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        # Unpack blob id, image length and image nonce
        length = struct.calcsize(cls._formatter)
        try:
            data = struct.unpack(cls._formatter, reader.readexactly(length))
        except struct.error as exc:
            raise MessageError('Could not unpack blob id, length and nonce') from exc
        blob_id, image_length, image_nonce = data

        # Download and decrypt image
        blob_id = binascii.hexlify(blob_id).decode('ascii')
        response = await connection.download(blob_id)
        image_data = await response.read()
        image = cls.decrypt(image_nonce, image_data, key_pair)

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'image': image,
            'mime_type': None,  # TODO: Guess mime type from bytes
        }))


# TODO: Update docstring (arguments)
@aio_run_proxy
class VideoMessage(Message):
    """
    A video message including a thumbnail.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

    Arguments for a new message:
        - `connection`: An instance of a connection.
        - `id`: Threema ID of the recipient.
        - `key`: The public key of the recipient. Will be fetched from
           the server if not supplied.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
        - `duration`: The duration of the video in seconds.
        - `video_path`: A file where the video is stored in.
        - `thumbnail_path`: The path to a thumbnail of the file.

    Arguments for an existing message:
        - `payload`: The remaining byte sequence of a decrypted
          message.
    """
    async_functions = {
        'pack',
        'unpack',
    }
    required_capabilities = {
        ReceptionCapability.video
    }
    _formatter = '<H{}sI{}sI{}s'.format(
        BLOB_ID_LENGTH, BLOB_ID_LENGTH, libnacl.crypto_box_SECRETKEYBYTES)

    def __init__(
            self, connection,
            duration=0,
            video=None, video_path=None,
            thumbnail_content=None, thumbnail_path=None,
            from_data=None, **kwargs
    ):
        super().__init__(connection, Message.Type.video_message,
                         from_data=from_data, **kwargs)
        if self._direction == self.Direction.outgoing:
            path_param = video_path is not None
            if sum((1 for param in (video, path_param) if param)) != 1:
                raise ValueError(("Either 'video' or 'video_path' need to be specified"))
            if sum((1 for param in (thumbnail_content, thumbnail_path) if param)) != 1:
                raise ValueError(("Either 'thumbnail_content' or 'thumbnail_path' "
                                  "need to be specified"))
            self.duration = duration
            self._video = video
            self._video_path = video_path
            self._thumbnail_content = thumbnail_content
            self._thumbnail_path = thumbnail_path
        else:
            self.duration = from_data['duration']
            self._video = from_data['video']
            self._video_path = None
            self._thumbnail_content = from_data['thumbnail_content']
            self._thumbnail_path = None

    @property
    def video(self):
        """
        Return the video as :class:`bytes`.

        Raises :exc:`OSError` in case the video could not be read from
        the specified path.
        """
        self._read_video()
        return self._video

    @property
    def thumbnail_content(self):
        """
        Return the thumbnails' content as :class:`bytes`.

        Raises :exc:`OSError` in case the thumbnails' content could
        not be read from the specified path.
        """
        self._read_thumbnail()
        return self._thumbnail_content

    def _read_video(self):
        """
        Read and store the video as :class:`bytes`.

        Raises :exc:`OSError` in case the video could not be read from
        the specified path.
        """
        if self._video is None:
            with open(self._video_path, mode='rb') as file:
                # Read content
                self._video = file.read()

    def _read_thumbnail(self):
        """
        Read and store the thumbnails' content as :class:`bytes`.

        Raises :exc:`OSError` in case the thumbnails' content could
        not be read from the specified path.
        """
        if self._thumbnail_content is None and self._thumbnail_path is not None:
            with open(self._thumbnail_path, mode='rb') as file:
                # Read content
                self._thumbnail_content = file.read()

    async def pack(self, writer):
        # Check capabilities of recipient
        await self.check_capabilities(self.required_capabilities)

        # Generate a symmetric key for the video and its thumbnail
        key, _ = Key.generate_secret_key()

        # Encrypt and upload video by a newly generated symmetric key
        _, video_data = _sk_encrypt(key, self.video, nonce=self.nonce['video'])
        video_id = await self._connection.upload(video_data)
        try:
            video_id = binascii.unhexlify(video_id)
        except binascii.Error as exc:
            raise MessageError('Could not convert hex-encoded blob id') from exc

        # Encrypt and upload thumbnail
        _, thumbnail_data = _sk_encrypt(
            key, self.thumbnail_content, nonce=self.nonce['thumbnail'])
        thumbnail_id = await self._connection.upload(thumbnail_data)
        try:
            thumbnail_id = binascii.unhexlify(thumbnail_id)
        except binascii.Error as exc:
            raise MessageError('Could not convert hex-encoded blob id') from exc

        # Pack duration, blob ids, video/thumbnail length and the secret key
        try:
            data = struct.pack(
                self._formatter,
                self.duration,
                video_id,
                len(self.video),
                thumbnail_id,
                len(self.thumbnail_content),
                key,
            )
        except struct.error as exc:
            raise MessageError(
                'Could not pack duration, blob ids, length and key') from exc

        # Add data
        writer.writeexactly(data)

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        # Unpack duration, blob ids, video/thumbnail length and the secret key
        length = struct.calcsize(cls._formatter)
        try:
            data = struct.unpack(cls._formatter, reader.readexactly(length))
        except struct.error as exc:
            raise MessageError(
                'Could not unpack duration, blob ids, length and key') from exc
        duration, video_id, video_length, thumbnail_id, thumbnail_length, key = data

        # Download and decrypt thumbnail
        thumbnail_id = binascii.hexlify(thumbnail_id).decode('ascii')
        response = await connection.download(thumbnail_id)
        thumbnail_data = await response.read()
        thumbnail_content = _sk_decrypt(key, cls.nonce['thumbnail'], thumbnail_data)

        # Validate thumbnail content length
        length = len(thumbnail_content)
        if length != thumbnail_length:
            message = 'Thumbnail content length does not match (expected: {}, got: {})'
            raise MessageError(message.format(thumbnail_length, length))

        # Download and decrypt video
        video_id = binascii.hexlify(video_id).decode('ascii')
        response = await connection.download(video_id)
        video_data = await response.read()
        video = _sk_decrypt(key, cls.nonce['file'], video_data)

        # Validate video content length
        length = len(video)
        if length != video_length:
            message = 'Video content length does not match (expected: {}, got: {})'
            raise MessageError(message.format(video_length, length))

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'duration': duration,
            'video': video,
            'thumbnail_content': thumbnail_content,
        }))


# TODO: Update docstring (arguments)
@aio_run_proxy
class FileMessage(Message):
    """
    A file message including a thumbnail.

    If the connection passed to the constructor is in blocking mode, then all
    methods on this class will be blocking too.

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
    async_functions = {
        'pack',
        'unpack',
    }
    required_capabilities = {
        ReceptionCapability.file
    }

    def __init__(
            self, connection,
            file_content=None, mime_type=None, file_name='file', file_path=None,
            thumbnail_content=None, thumbnail_path=None,
            from_data=None, **kwargs
    ):
        super().__init__(connection, Message.Type.file_message,
                         from_data=from_data, **kwargs)
        if self._direction == self.Direction.outgoing:
            file_and_mime = all((param is not None for param
                                 in [file_content, mime_type]))
            path_param = file_path is not None
            if sum((1 for param in (file_and_mime, path_param) if param)) != 1:
                raise ValueError(("Either 'file_content' and 'mime_type' or 'file_path' "
                                  "need to be specified"))
            if sum((1 for param in (thumbnail_content, thumbnail_path) if param)) > 1:
                raise ValueError(("Either 'thumbnail_content' or 'thumbnail_path' may "
                                  "to be specified"))
            self._file_content = file_content
            self._mime_type = mime_type
            self._file_name = file_name
            self._file_path = file_path
            self._thumbnail_content = thumbnail_content
            self._thumbnail_path = thumbnail_path
        else:
            self._file_content = from_data['file_content']
            self._mime_type = from_data['mime_type']
            self._file_name = from_data['file_name']
            self._file_path = None
            self._thumbnail_content = from_data['thumbnail_content']
            self._thumbnail_path = None

    @property
    def file_content(self):
        """
        Return the files' content as :class:`bytes`.

        Raises :exc:`OSError` in case the files' content could not be
        read from the specified path.
        """
        self._read_file()
        return self._file_content

    @property
    def mime_type(self):
        """
        Return the mime type of the file as :class:`str`.
        """
        self._read_file()
        return self._mime_type

    @property
    def thumbnail_content(self):
        """
        Return the thumbnails' content as :class:`bytes`.

        Raises :exc:`OSError` in case the thumbnails' content could
        not be read from the specified path.
        """
        self._read_thumbnail()
        return self._thumbnail_content

    def _read_file(self):
        """
        Read and store the files' content as :class:`bytes`.

        Raises :exc:`OSError` in case the files' content could not be
        read from the specified path.
        """
        if self._file_content is None:
            with open(self._file_path, mode='rb') as file:
                # Read content
                self._file_content = file.read()

            # Guess the mime type
            mime_type, _ = mimetypes.guess_type(self._file_path)
            if mime_type is None:
                # Fallback mime type
                mime_type = 'application/octet-stream'
            self._mime_type = mime_type

    def _read_thumbnail(self):
        """
        Read and store the thumbnails' content as :class:`bytes`.

        Raises :exc:`OSError` in case the thumbnails' content could
        not be read from the specified path.
        """
        if self._thumbnail_content is None and self._thumbnail_path is not None:
            with open(self._thumbnail_path, mode='rb') as file:
                # Read content
                self._thumbnail_content = file.read()

    async def pack(self, writer):
        # Check capabilities of recipient
        await self.check_capabilities(self.required_capabilities)

        # Encrypt and upload file by a newly generated symmetric key
        key, hex_key = Key.generate_secret_key()
        _, file_data = _sk_encrypt(key, self.file_content, nonce=self.nonce['file'])
        file_id = await self._connection.upload(file_data)

        # Build JSON
        if self._file_path is not None:
            file_name = os.path.basename(self._file_path)
        else:
            file_name = self._file_name
        content = {
            'b': file_id,
            'k': hex_key.decode('ascii'),
            'm': self.mime_type,
            'n': file_name,
            's': len(self.file_content),
            'i': 0,
        }

        # Encrypt and upload thumbnail (if any)
        thumbnail_content = self.thumbnail_content
        if thumbnail_content is not None:
            _, thumbnail_data = _sk_encrypt(
                key, thumbnail_content, nonce=self.nonce['thumbnail'])
            thumbnail_id = await self._connection.upload(thumbnail_data)
            # Update JSON
            content['t'] = thumbnail_id

        # Pack payload (compact JSON encoding)
        try:
            content = json.dumps(content, separators=(',', ':')).encode('ascii')
        except UnicodeError as exc:
            raise MessageError('Could not encode JSON') from exc

        # Add payload
        writer.writeexactly(content)

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        # Get payload
        try:
            content = bytes(reader.readexactly(len(reader))).decode('ascii')
        except UnicodeError as exc:
            raise MessageError('Could not decode JSON') from exc

        # Unpack payload from JSON
        try:
            content = json.loads(content)
        except UnicodeError as exc:
            raise MessageError('Could not decode JSON') from exc
        except ValueError as exc:
            raise MessageError('Could not load JSON') from exc

        # Unpack JSON
        try:
            file_id = content['b']
            key = binascii.unhexlify(content['k'])
            mime_type = content['m']
            file_name = content['n']
            file_content_length = content['s']
        except KeyError as exc:
            raise MessageError('Invalid JSON payload') from exc
        except binascii.Error as exc:
            raise MessageError('Could not convert hex-encoded secret key') from exc
        thumbnail_id = content.get('t')

        # Download and decrypt thumbnail (if any)
        if thumbnail_id is not None:
            response = await connection.download(thumbnail_id)
            thumbnail_data = await response.read()
            thumbnail_content = _sk_decrypt(key, cls.nonce['thumbnail'], thumbnail_data)
        else:
            thumbnail_content = None

        # Download and decrypt file
        response = await connection.download(file_id)
        file_data = await response.read()
        file_content = _sk_decrypt(key, cls.nonce['file'], file_data)

        # Validate file content length
        length = len(file_content)
        if length != file_content_length:
            message = 'File content length does not match (expected: {}, got: {})'
            raise MessageError(message.format(file_content_length, length))

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'file_content': file_content,
            'mime_type': mime_type,
            'file_name': file_name,
            'thumbnail_content': thumbnail_content,
        }))
