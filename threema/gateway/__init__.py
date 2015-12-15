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
import enum

import requests
import libnacl.public
import libnacl.encode

from . import exception
from .exception import *
from .key import Key

__author__ = 'Lennart Grahl <lennart.grahl@threema.ch>'
__status__ = 'Production'
__version__ = '1.1.9'
__all__ = (
    'feature_level',
    'ReceptionCapability',
    'Connection',
) + exception.__all__

feature_level = 3


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


# noinspection PyShadowingNames,PyShadowingBuiltins
class Connection:
    """
    Container for the sender's Threema ID and the Threema Gateway
    secret. Can be applied to multiple messages for both simple and
    end-to-end mode.

    Arguments:
        - `id`: Threema ID of the sender.
        - `secret`: Threema Gateway secret.
        - `key`: Private key of the sender. Only required for
          end-to-end mode.
        - `key_file`: A file where the private key is stored in. Can
          be used instead of passing the key directly.
    """
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

    def __init__(self, id, secret, key=None, key_file=None):
        self._session = requests.Session()
        self._key = None
        self._key_file = None
        self.id = id
        self.secret = secret
        self.key = key
        self.key_file = key_file

    @property
    def key(self):
        """
        Get the private key of the sender.

        Set the private key of the sender. The key will be decoded
        if required.
        """
        if self._key is None:
            raise GatewayKeyError("Sender's private key not specified")
        return self._key

    @key.setter
    def key(self, key):
        if isinstance(key, str):
            key = Key.decode(key, Key.Type.private)
        self._key = key

    @property
    def key_file(self):
        """
        Get the path of the sender's private key file.

        Set the private key of the sender by reading it from a file.
        """
        return self._key_file

    @key_file.setter
    def key_file(self, key_file):
        if key_file is not None:
            with open(key_file) as file:
                self.key = file.readline().strip()
        self._key_file = key_file

    def get_public_key(self, id):
        """
        Get the public key of a Threema ID.

        Arguments:
            - `id`: A Threema ID.

        Return a :class:`libnacl.public.PublicKey` for a Threema ID.
        """
        response = self._get(self.urls['get_public_key'].format(id))
        if response.status_code == 200:
            key = libnacl.encode.hex_decode(response.text)
            return libnacl.public.PublicKey(key)
        else:
            raise KeyServerError(response.status_code)

    def get_id(self, **mode):
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
        if len(mode) > 1:
            raise IDError('Use (only) one of the possible modes to get a Threema ID')

        # Select mode and start request
        mode, value = mode.popitem()
        response = self._get(self.urls[modes[mode]].format(value))
        if response.status_code == 200:
            return response.text
        else:
            raise IDServerError(response.status_code)

    def get_reception_capabilities(self, id):
        """
        Get the reception capabilities of a Threema ID.

        Arguments:
            - `id`: A Threema ID.

        Return a set containing items from :class:`ReceptionCapability`.
        """
        response = self._get(self.urls['get_reception_capabilities'].format(id))
        if response.status_code == 200:
            try:
                return {ReceptionCapability(capability.strip())
                        for capability in response.text.split(',')}
            except ValueError as exc:
                raise ReceptionCapabilitiesError('Invalid reception capability') from exc
        else:
            raise ReceptionCapabilitiesServerError(response.status_code)

    def get_credits(self):
        """
        Return the number of credits left on the account.
        """
        response = self._get(self.urls['get_credits'])
        if response.status_code == 200:
            return int(response.text)
        else:
            raise CreditsServerError(response.status_code)

    def send_simple(self, **data):
        """
        Send a message by using the simple mode.

        Arguments:
            - `data`: A dictionary containing POST data.

        Return the ID of the message.
        """
        return self._send(self.urls['send_simple'], data)

    def send_e2e(self, **data):
        """
        Send a message by using the end-to-end mode.

        Arguments:
            - `data`: A dictionary containing POST data.

        Return the ID of the message.
        """
        return self._send(self.urls['send_e2e'], data)

    def upload(self, data):
        """
        Upload a blob.

        Arguments:
            - `data`: Binary data.

        Return the ID of the blob.
        """
        return self._upload(self.urls['upload_blob'], data)

    def download(self, id):
        """
        Download a blob.

        Arguments:
            - `id`: The blob ID.

        Return binary data.
        """
        response = self._get(self.urls['download_blob'].format(id))
        if response.status_code == 200:
            return response.content
        else:
            raise BlobServerError(response.status_code)

    def _get(self, *args, **kwargs):
        """
        Wrapper for :func:`requests.get` that injects the connection's
        Threema ID and its secret.

        Return a :class:`requests.Response` instance.
        """
        kwargs.setdefault('params', {})
        kwargs['params'].setdefault('from', self.id)
        kwargs['params'].setdefault('secret', self.secret)
        return self._session.get(*args, **kwargs)

    def _send(self, url, data):
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
        response = self._session.post(url, data=data)
        if response.status_code == 200:
            return response.text
        else:
            raise MessageServerError(response.status_code)

    def _upload(self, url, data):
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
        response = self._session.post(url, params=params, files=files)
        if response.status_code == 200:
            return response.text
        else:
            raise BlobServerError(response.status_code)
