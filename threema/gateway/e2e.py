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
import ssl
import hmac
import hashlib
import datetime

import libnacl
import libnacl.public
import libnacl.secret
import libnacl.encode

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher

from . import ReceptionCapability, util
from .exception import *
from .key import Key

__all__ = (
    'BLOB_ID_LENGTH',
    'AbstractCallback',
    'Message',
    'DeliveryReceipt',
    'TextMessage',
    'ImageMessage',
    'FileMessage',
)

BLOB_ID_LENGTH = 16


# TODO: Raises?
def _pk_encrypt(key_pair, data, nonce=None):
    """
    Encrypt data by using public-key encryption.

    Arguments:
        - `key_pair`: A tuple containing our private key and the public
          key of the recipient.
        - `data`: Raw data (bytes).
        - `nonce`: A predefined nonce.

    Return a tuple of bytes containing the nonce and the encrypted
    data.
    """
    # Assemble and encrypt the payload
    private, public = key_pair
    box = libnacl.public.Box(sk=private, pk=public)
    return box.encrypt(data, nonce=nonce, pack_nonce=False)


# TODO: Raises?
def _pk_decrypt(key_pair, nonce, data):
    """
    Decrypt data by using public-key decryption.

    Arguments:
        - `key_pair`: A tuple containing our private key and the public
          key of the sender.
        - `nonce`: The nonce of the encrypted data.
        - `data`: Encrypted data (bytes).

    Return the decrypted data.
    """
    # Decrypt payload
    private, public = key_pair
    box = libnacl.public.Box(sk=private, pk=public)
    return box.decrypt(data, nonce=nonce)


# TODO: Raises?
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


# TODO: Raises?
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


# TODO: Add logging
# TODO: Add docstrings
class AbstractCallback(metaclass=abc.ABCMeta):
    """
    Raises :exc:`TypeError` in case no valid certificate has been
    provided.
    """
    def __init__(self, connection, loop=None):
        self.connection = connection
        # Note: I'm guessing here the secret must be ASCII
        self.encoded_secret = connection.secret.encode('ascii')
        self.loop = asyncio.get_event_loop() if loop is None else loop
        # Create router
        self.router = self.create_router()
        # Create application
        self.application = self.create_application(self.router, loop)
        self.handler = self.create_handler()
        self.server = None

    # noinspection PyMethodMayBeStatic
    def create_ssl_context(self, certfile, keyfile=None):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return ssl_context

    def create_router(self):
        router = UrlDispatcher()
        router.add_route('POST', '/gateway_callback', self._handle_and_catch_error)
        return router

    # noinspection PyMethodMayBeStatic
    def create_application(self, router, loop):
        return web.Application(router=router, loop=loop)

    def create_handler(self):
        return self.application.make_handler()

    @asyncio.coroutine
    def create_server(self, certfile, keyfile=None, host=None, port=443, **kwargs):
        # Create SSL context
        ssl_context = self.create_ssl_context(certfile, keyfile=keyfile)
        # Create server
        # noinspection PyArgumentList
        server = yield from self.loop.create_server(
            self.handler, host=host, port=port, ssl=ssl_context, **kwargs)
        return server

    @asyncio.coroutine
    def close(self, timeout=10.0):
        # Stop handler and application
        yield from self.application.shutdown()
        yield from self.handler.finish_connections(timeout=timeout)
        yield from self.application.cleanup()

    @asyncio.coroutine
    def _handle_and_catch_error(self, request):
        try:
            return (yield from self.handle_callback(request))
        except CallbackError as exc:
            # TODO: Log
            # Note: For security reasons, we do not send the reason
            return web.Response(status=exc.status)
        except Exception:
            # TODO: Log
            raise

    # TODO: Raises?
    @asyncio.coroutine
    def handle_callback(self, request):
        response = yield from request.post()

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

        # Validate MAC and ID
        self.validate_mac(mac, response)
        self.validate_id(to_id)

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
            message = yield from Message.receive(self.connection, {
                'from_id': from_id,
                'message_id': message_id,
                'date': date,
            }, nonce, data)
        except MessageError as exc:
            raise CallbackError(400, str(exc)) from exc

        # Pass message to handler
        try:
            yield from self.receive_message(message)
        except TypeError:
            # TODO: Log error that the inherited method 'receive_message' MUST
            #       be a coroutine.
            raise

        # Respond with 'OK'
        return web.Response(status=200)

    def validate_mac(self, expected_mac, response):
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
        hmac_ = hmac.new(self.encoded_secret, msg=message, digestmod=hashlib.sha256)
        actual_mac = hmac_.hexdigest()
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise CallbackError(400, 'MACs do not match')

    def validate_id(self, to_id):
        if to_id != self.connection.id:
            raise CallbackError(400, 'IDs do not match')

    @asyncio.coroutine
    @abc.abstractmethod
    def receive_message(self, message):
        raise NotImplementedError


# TODO: Update docstring (arguments)
class Message(metaclass=abc.ABCMeta):
    """
    A message class all end-to-end mode messages are derived from.

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
    nonce = {
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
                cls.Type.file_message: FileMessage,
                cls.Type.delivery_receipt: DeliveryReceipt,
            }
        return cls._message_classes[type_]

    def __init__(
            self, connection, type_,
            key=None, key_file=None,
            to_id=None, from_data=None
    ):
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
    @asyncio.coroutine
    def key(self):
        """
        Get the public key of the recipient (outgoing messages) or the
        sender (incoming messages). Will be request from the server
        if necessary. Note that the getter is a coroutine!

        Set the public key of the recipient or sender. The key will be
        decoded if required.
        """
        if self._key is None:
            self._key = yield from self._connection.get_public_key(self.to_id)
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
    @asyncio.coroutine
    def send(self, get_data_only=False):
        """
        Send a message.

        Raises :exc:`DirectionError` in case the message is not intended
        to be sent.
        """
        if self._direction != self.Direction.outgoing:
            raise DirectionError('Parameters are missing to send the message')
        writer = util.ViewIOWriter()

        # Pack type
        try:
            writer.writeexactly(struct.pack('<B', self.type.value))
        except struct.error as exc:
            raise MessageError('Could not pack type') from exc

        # Get content data
        yield from self.pack(writer)

        # Generate 0 < padding < 256
        padding_length = util.randint(1, 255)
        # Add padding to data
        writer.writeexactly(bytes([padding_length] * padding_length))

        # Encrypt message
        nonce, data = yield from self.encrypt(writer.getvalue())
        if get_data_only:
            return nonce, data

        # Send message
        return (yield from self._connection.send_e2e(**{
            'to': self.to_id,
            'nonce': binascii.hexlify(nonce).decode('ascii'),
            'box': binascii.hexlify(data).decode('ascii')
        }))

    # TODO: Raises?
    @classmethod
    @asyncio.coroutine
    def receive(cls, connection, parameters, nonce, data):
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
        key_pair = yield from cls.get_decrypt_key_pair(connection, parameters)
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
        reader = util.ViewIOReader(data[1:-padding_length])

        # Unpack message
        return (yield from class_.unpack(connection, parameters, key_pair, reader))

    @asyncio.coroutine
    @abc.abstractmethod
    def pack(self, writer):
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
    @asyncio.coroutine
    @abc.abstractmethod
    def unpack(cls, connection, parameters, key_pair, reader):
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
    @asyncio.coroutine
    def check_capabilities(self, required_capabilities):
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
        recipient_capabilities = yield from capabilities_coroutine
        if not required_capabilities <= recipient_capabilities:
            missing_capabilities = required_capabilities - recipient_capabilities
            raise MissingCapabilityError(missing_capabilities)

    # TODO: Raises?
    @property
    @asyncio.coroutine
    def get_encrypt_key_pair(self):
        """
        Return a tuple containing our private key and the public key of
        the recipient.
        """
        private = self._connection.key
        public = yield from self.key
        return private, public

    # TODO: Raises?
    @classmethod
    @asyncio.coroutine
    def get_decrypt_key_pair(cls, connection, parameters):
        """
        Return a tuple containing our private key and the public key of
        the sender.

        Arguments:
            - `connection`: A :class:`Connection` instance.
            - `parameters`: Parameters passed to
              :method:`Message.unpack`.
        """
        private = connection.key
        public = yield from connection.get_public_key(parameters['from_id'])
        return private, public

    @asyncio.coroutine
    def encrypt(self, data, key_pair=None, nonce=None):
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
            key_pair = yield from self.get_encrypt_key_pair

        # Encrypt
        try:
            return _pk_encrypt(key_pair, data, nonce=nonce)
        except ValueError as exc:
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
        except ValueError:
            raise MessageError('Could not decrypt data')


# TODO: Update docstring (arguments)
class DeliveryReceipt(Message):
    """
    A delivery receipt that can be received in end-to-end mode.
    Each delivery receipt message confirms the receipt of one
    or multiple regular text messages.

    .. note:: Sending delivery receipts is not officially supported.

    Arguments:
        - `payload`: The remaining byte sequence of the message.
    """
    @enum.unique
    class ReceiptType(enum.IntEnum):
        """
        Describes message receipt types.

        .. warning:: `user_ack` is deprecated and will be removed with
           the next major release. Use `user_acknowledge` instead.
        """
        received = 0x01
        read = 0x02
        user_acknowledge = user_ack = 0x03
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

    @asyncio.coroutine
    def pack(self, writer):
        # Pack content
        try:
            writer.writeexactly(struct.pack('<B', self.receipt_type.value))
        except struct.error as exc:
            raise MessageError('Could not pack receipt type') from exc
        for message_id in self.message_ids:
            writer.writeexactly(message_id)

    @classmethod
    @asyncio.coroutine
    def unpack(cls, connection, parameters, key_pair, reader):
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

    @asyncio.coroutine
    def pack(self, writer):
        # Encode text
        try:
            text = self.text.encode('utf-8')
        except UnicodeError as exc:
            raise MessageError('Could not encode text') from exc

        # Add text
        writer.writeexactly(text)

    @classmethod
    @asyncio.coroutine
    def unpack(cls, connection, parameters, key_pair, reader):
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

    @asyncio.coroutine
    def pack(self, writer):
        # Check capabilities of recipient
        yield from self.check_capabilities(self.required_capabilities)

        # Encrypt and upload image
        image_nonce, image_data = yield from self.encrypt(self.image)
        blob_id = yield from self._connection.upload(image_data)
        try:
            blob_id = binascii.unhexlify(blob_id)
        except binascii.Error as exc:
            raise MessageError('Could not convert hex-encoded blob id') from exc

        # Pack blob id, image length and image nonce
        try:
            data = struct.pack(self._formatter, blob_id, len(image_data), image_nonce)
        except struct.error as exc:
            raise MessageError('Could not pack blob id, length and nonce') from exc

        # Add data
        writer.writeexactly(data)

    @classmethod
    @asyncio.coroutine
    def unpack(cls, connection, parameters, key_pair, reader):
        # Unpack blob id, image length and image nonce
        length = struct.calcsize(cls._formatter)
        try:
            data = struct.unpack(cls._formatter, reader.readexactly(length))
        except struct.error as exc:
            raise MessageError('Could not unpack blob id, length and nonce') from exc
        blob_id, image_length, image_nonce = data

        # Download and decrypt image
        blob_id = binascii.hexlify(blob_id).decode('ascii')
        response = yield from connection.download(blob_id)
        image_data = yield from response.read()
        image = cls.decrypt(image_nonce, image_data, key_pair)

        # Return instance
        return cls(connection, from_data=dict(parameters, **{
            'image': image,
            'mime_type': None,  # TODO: Guess mime type from bytes
        }))


# TODO: Update docstring (arguments)
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

    @asyncio.coroutine
    def pack(self, writer):
        # Check capabilities of recipient
        yield from self.check_capabilities(self.required_capabilities)

        # Encrypt and upload file by a newly generated symmetric key
        key, hex_key = Key.generate_secret_key()
        _, file_data = _sk_encrypt(key, self.file_content, nonce=self.nonce['file'])
        file_id = yield from self._connection.upload(file_data)

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
            thumbnail_id = yield from self._connection.upload(thumbnail_data)
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
    @asyncio.coroutine
    def unpack(cls, connection, parameters, key_pair, reader):
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
            response = yield from connection.download(thumbnail_id)
            thumbnail_data = yield from response.read()
            thumbnail_content = _sk_decrypt(key, cls.nonce['thumbnail'], thumbnail_data)
        else:
            thumbnail_content = None

        # Download and decrypt file
        response = yield from connection.download(file_id)
        file_data = yield from response.read()
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
