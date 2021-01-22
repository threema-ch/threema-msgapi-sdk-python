import binascii
import enum

import aiohttp
import libnacl.encode
import libnacl.public

from .exception import (
    BlobServerError,
    CreditsServerError,
    GatewayKeyError,
    IDError,
    IDServerError,
    KeyServerError,
    MessageServerError,
    ReceptionCapabilitiesError,
    ReceptionCapabilitiesServerError,
)
from .key import Key
from .util import (
    AioRunMixin,
    aio_run_proxy,
    async_ttl_cache,
    raise_server_error,
)

__all__ = (
    'ReceptionCapability',
    'Connection',
)


@enum.unique
class ReceptionCapability(enum.Enum):
    """
    The reception capability of a Threema ID.
    """
    text = 'text'
    image = 'image'
    video = 'video'
    audio = 'audio'
    file = 'file'


@aio_run_proxy
class Connection(AioRunMixin):
    """
    Container for the sender's Threema ID and the Threema Gateway
    secret. Can be applied to multiple messages for both simple and
    end-to-end mode.

    You should either use the `with` statement on this class or call
    :func:`~Connection.close` after you are done querying the Threema
    Gateway Service API. Be aware that the connection instance cannot be
    reused once it has been closed. This also applies to the `with`
    statement (e.g. the instance can be used in one `with` block only).
    A closed connection instance will raise :exc:`RuntimeError`
    indicating that the underlying HTTP session has been closed.

    The connection can work both in non-blocking (through asyncio) and
    blocking mode. If you want to use the API in a blocking way (which
    implicitly starts an event loop to process the requests), then
    instantiate this class with ``blocking=True``.

    Arguments:
        - `id`: Threema ID of the sender.
        - `secret`: Threema Gateway secret.
        - `key`: Private key of the sender. Only required for
          end-to-end mode.
        - `key_file`: A file where the private key is stored
          in. Can be used instead of passing the key directly.
        - `fingerprint`: A binary fingerprint of an DER-encoded TLS
          certificate. Will fall back to a stored fingerprint which will
          be invalid as soon as the certificate expires.
        - `verify_fingerprint`: Set to `True` if you want to verify the
          TLS certificate of the Threema Gateway Server by a
          fingerprint. (Recommended)
        - `blocking`: Whether to use a blocking API, without the need
          for an explicit event loop.
    """
    async_functions = {
        '__exit__',
        'get_public_key',
        'get_id',
        'get_reception_capabilities',
        'get_credits',
        'send_simple',
        'send_e2e',
        'upload',
        'download',
    }
    fingerprint = binascii.unhexlify(
        b'42b1038e72f00c8c4dad78a3ebdc6d7a50c5ef288da9019b9171e4d675c08a17')
    urls = {
        'get_public_key': 'https://msgapi.threema.ch/pubkeys/{}',
        'get_id_by_phone': 'https://msgapi.threema.ch/lookup/phone/{}',
        'get_id_by_phone_hash': 'https://msgapi.threema.ch/lookup/phone_hash/{}',
        'get_id_by_email': 'https://msgapi.threema.ch/lookup/email/{}',
        'get_id_by_email_hash': 'https://msgapi.threema.ch/lookup/email_hash/{}',
        'get_reception_capabilities': 'https://msgapi.threema.ch/capabilities/{}',
        'get_credits': 'https://msgapi.threema.ch/credits',
        'send_simple': 'https://msgapi.threema.ch/send_simple',
        'send_e2e': 'https://msgapi.threema.ch/send_e2e',
        'upload_blob': 'https://msgapi.threema.ch/upload_blob',
        'download_blob': 'https://msgapi.threema.ch/blobs/{}'
    }

    def __init__(
            self, identity, secret,
            key=None, key_file=None,
            fingerprint=None, verify_fingerprint=False, blocking=False,
    ):
        super().__init__(blocking=blocking)
        if fingerprint is None and verify_fingerprint:
            fingerprint = self.fingerprint
        if fingerprint is not None:
            fingerprint = aiohttp.Fingerprint(fingerprint)
        connector = aiohttp.TCPConnector(ssl=fingerprint)
        self._session = aiohttp.ClientSession(connector=connector)
        self._key = None
        self._key_file = None
        self.id = identity
        self.secret = secret
        self.key = key
        self.key_file = key_file

    def __enter__(self):
        if not self.blocking:
            raise RuntimeError("Use `async with` in async mode")
        return self

    async def __exit__(self, *_):
        await self.close()

    async def __aenter__(self):
        if self.blocking:
            raise RuntimeError("Use `with` in blocking mode")
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        """
        Close the underlying :class:`aiohttp.ClientSession`.
        """
        await self._session.close()

    @property
    def key(self):
        """Return the private key."""
        if self._key is None:
            raise GatewayKeyError("Sender's private key not specified")
        return self._key

    @key.setter
    def key(self, key):
        """Set the private key. The key will be decoded if required."""
        if isinstance(key, str):
            key = Key.decode(key, Key.Type.private)
        self._key = key

    @property
    def key_file(self):
        """Get the path of the private key file."""
        return self._key_file

    @key_file.setter
    def key_file(self, key_file):
        """Set the private key by reading it from a file."""
        if key_file is not None:
            with open(key_file) as file:
                self.key = file.readline().strip()
        self._key_file = key_file

    @async_ttl_cache(ttl=60 * 60)
    async def get_public_key(self, id_):
        """
        Get the public key of a Threema ID.

        Arguments:
            - `id_`: A Threema ID.

        Return a :class:`libnacl.public.PublicKey` for a Threema ID.
        """
        response = await self._get(self.urls['get_public_key'].format(id_))
        if response.status == 200:
            text = await response.text()
            key = libnacl.encode.hex_decode(text)
            return libnacl.public.PublicKey(key)
        else:
            await raise_server_error(response, KeyServerError)

    @async_ttl_cache(ttl=60 * 60)
    async def get_id(self, **mode):
        """
        Get a user's Threema ID.

        Use **only one** of the arguments described below.

        Arguments:
            - `phone`: A phone number in E.164 format without the
              leading `+`.
            - `phone_hash`: An HMAC-SHA256 hash of an E.164 phone
              number without the leading `+`.
            - `email`: A lowercase email address.
            - `email_hash`: An HMAC-SHA256 hash of a lowercase and
              whitespace-trimmed email address.

        Return the Threema ID.
        """
        modes = {
            'phone': 'get_id_by_phone',
            'phone_hash': 'get_id_by_phone_hash',
            'email': 'get_id_by_email',
            'email_hash': 'get_id_by_email_hash'
        }

        # Check mode
        if len(set(mode) - set(modes)) > 0:
            raise IDError('Unknown mode selected: {}'.format(set(mode)))
        mode_length = len(mode)
        if mode_length > 1 or mode_length == 0:
            raise IDError('Use (only) one of the possible modes to get a Threema ID')

        # Select mode and start request
        mode, value = mode.popitem()
        response = await self._get(self.urls[modes[mode]].format(value))
        if response.status == 200:
            return await response.text()
        else:
            await raise_server_error(response, IDServerError)

    @async_ttl_cache(ttl=5 * 60)
    async def get_reception_capabilities(self, id_):
        """
        Get the reception capabilities of a Threema ID.

        Arguments:
            - `id_`: A Threema ID.

        Return a set containing items from :class:`ReceptionCapability`.
        """
        get_coroutine = self._get(self.urls['get_reception_capabilities'].format(id_))
        response = await get_coroutine
        if response.status == 200:
            try:
                text = await response.text()
                return {ReceptionCapability(capability.strip())
                        for capability in text.split(',')}
            except ValueError as exc:
                await response.release()
                raise ReceptionCapabilitiesError('Invalid reception capability') from exc
        else:
            await raise_server_error(response, ReceptionCapabilitiesServerError)

    async def get_credits(self):
        """
        Return the number of credits left on the account.
        """
        response = await self._get(self.urls['get_credits'])
        if response.status == 200:
            text = await response.text()
            return int(text)
        else:
            await raise_server_error(response, CreditsServerError)

    async def send_simple(self, **data):
        """
        Send a message by using the simple mode.

        Arguments:
            - `data`: A dictionary containing POST data.

        Return the ID of the message.
        """
        return await self._send(self.urls['send_simple'], data)

    async def send_e2e(self, **data):
        """
        Send a message by using the end-to-end mode.

        Arguments:
            - `data`: A dictionary containing POST data.

        Return the ID of the message.
        """
        return await self._send(self.urls['send_e2e'], data)

    async def upload(self, data):
        """
        Upload a blob.

        Arguments:
            - `data`: Binary data.

        Return the hex-encoded ID of the blob.
        """
        return await self._upload(self.urls['upload_blob'], data)

    async def download(self, blob_id):
        """
        Download a blob.

        Arguments:
            - `id`: The hex-encoded blob ID.

        Return a :class:`asyncio.StreamReader` instance.
        """
        response = await self._get(self.urls['download_blob'].format(blob_id))
        if response.status == 200:
            return response.content
        else:
            await raise_server_error(response, BlobServerError)

    async def _get(self, *args, **kwargs):
        """
        Wrapper for :func:`requests.get` that injects the connection's
        Threema ID and its secret.

        Return a :class:`aiohttp.ClientResponse` instance.
        """
        kwargs.setdefault('params', {})
        kwargs['params'].setdefault('from', self.id)
        kwargs['params'].setdefault('secret', self.secret)
        return await self._session.get(*args, **kwargs)

    async def _send(self, url, data):
        """
        Send a message.

        Arguments:
            - `url`: URL for the request.
            - `data`: A dictionary containing POST data.

        Return the ID of the message.
        """
        # Inject Threema ID and secret
        data.setdefault('from', self.id)
        data.setdefault('secret', self.secret)

        # Send message
        response = await self._session.post(url, data=data)
        if response.status == 200:
            return await response.text()
        else:
            await raise_server_error(response, MessageServerError)

    async def _upload(self, url, data):
        """
        Upload a blob.

        Arguments:
            - `data`: Binary data.

        Return the ID of the blob.
        """
        # Inject Threema ID and secret
        params = {'from': self.id, 'secret': self.secret}

        # Prepare multipart encoded file
        files = {'blob': data}

        # Send message
        response = await self._session.post(url, params=params, data=files)
        if response.status == 200:
            return await response.text()
        else:
            await raise_server_error(response, BlobServerError)
