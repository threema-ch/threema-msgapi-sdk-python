import enum
import io

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

_DEFAULT_BASE_URL = "https://msgapi.threema.ch"


@enum.unique
class ReceptionCapability(enum.Enum):
    """
    The reception capability of a Threema ID.
    """
    text = 'text'
    image = 'image'
    group = 'group'
    audio = 'audio'
    video = 'video'
    file = 'file'
    poll = 'ballot'
    one_to_one_audio_call = 'call'
    one_to_one_video_call = 'videocall'
    perfect_forward_security = 'pfs'
    group_call = 'groupcall'


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
        - `blocking`: Whether to use a blocking API, without the need
          for an explicit event loop.
        - `session`: An optional :class:`aiohttp.ClientSession`.
        - `session_kwargs`: Additional key value arguments passed to the
          client session on each call to `get` and `post`.
        - `base_url`: Base URL of the Threema Gateway. Defaults to
          "https://msgapi.threema.ch".
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

    def __init__(
            self, identity, secret,
            key=None, key_file=None,
            blocking=False, session=None, session_kwargs=None,
            base_url=None,
    ):
        super().__init__(blocking=blocking)
        self._session = session if session is not None else aiohttp.ClientSession()
        self._session_kwargs = session_kwargs if session_kwargs is not None else {}
        self._key = None
        self._key_file = None
        self.id = identity
        self.secret = secret
        self.key = key
        self.key_file = key_file

        self._base_url = (base_url or _DEFAULT_BASE_URL).rstrip('/')
        self.urls = self._build_urls(self._base_url)

    @staticmethod
    def _build_urls(base_url: str) -> dict:
        return {
            'get_public_key': f'{base_url}/pubkeys/{{}}',
            'get_id_by_phone': f'{base_url}/lookup/phone/{{}}',
            'get_id_by_phone_hash': f'{base_url}/lookup/phone_hash/{{}}',
            'get_id_by_email': f'{base_url}/lookup/email/{{}}',
            'get_id_by_email_hash': f'{base_url}/lookup/email_hash/{{}}',
            'get_reception_capabilities': f'{base_url}/capabilities/{{}}',
            'get_credits': f'{base_url}/credits',
            'send_simple': f'{base_url}/send_simple',
            'send_e2e': f'{base_url}/send_e2e',
            'upload_blob': f'{base_url}/upload_blob',
            'download_blob': f'{base_url}/blobs/{{}}'
        }


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
        Get the reception capabilities of a Threema ID. Unknown capabilities are
        being discarded.

        Arguments:
            - `id_`: A Threema ID.

        Return a set containing items from :class:`ReceptionCapability`.
        """
        get_coroutine = self._get(self.urls['get_reception_capabilities'].format(id_))
        response = await get_coroutine
        if response.status == 200:
            text = await response.text()
            capabilities = set()
            for capability in text.split(','):
                try:
                    capabilities.add(ReceptionCapability(capability.strip()))
                except ValueError:
                    pass
            return capabilities
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
        return await self._upload(self.urls['upload_blob'], data=io.BytesIO(data))

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
        kwargs = {**self._session_kwargs, **kwargs}
        kwargs.setdefault('params', {})
        kwargs['params'].setdefault('from', self.id)
        kwargs['params'].setdefault('secret', self.secret)
        return await self._session.get(*args, **kwargs)

    async def _send(self, url, data, **kwargs):
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
        kwargs = {**self._session_kwargs, **kwargs}
        response = await self._session.post(url, data=data, **kwargs)
        if response.status == 200:
            return await response.text()
        else:
            await raise_server_error(response, MessageServerError)

    async def _upload(self, url, data, **kwargs):
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
        kwargs = {**self._session_kwargs, **kwargs}
        response = await self._session.post(url, params=params, data=files, **kwargs)
        if response.status == 200:
            return await response.text()
        else:
            await raise_server_error(response, BlobServerError)
