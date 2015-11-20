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

from threema.gateway.key import Key

__author__ = 'Lennart Grahl <lennart.grahl@threema.ch>'
__status__ = 'Production'
__version__ = '1.0.0'
__all__ = ('GatewayError', 'GatewayServerError', 'IDError', 'IDServerError', 'KeyError',
           'KeyServerError', 'MessageError', 'MessageServerError', 'Connection')


class GatewayError(Exception):
    """
    General error of this module. All other exceptions are derived from
    this class.
    """
    pass


class GatewayServerError(GatewayError):
    """
    The server has responded with an error code. All other server
    exceptions are derived from this class.

    Arguments:
        - `response`: An instance of a :class:`requests.Response`
          object.
    """
    status_description = {}

    def __init__(self, response):
        self.response = response

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        status_code = self.response.status_code

        # Return description for status code
        try:
            return self.status_description[status_code]
        except KeyError:
            return 'Unknown error, status code: {}'.format(status_code)


class IDError(GatewayError):
    """
    A problem before fetching a Threema ID occurred.
    """
    pass


class IDServerError(IDError, GatewayServerError):
    """
    The server has responded with an error code while looking up a
    Threema ID.
    """
    status_description = {
        400: 'Supplied hash invalid',
        401: 'API identity or secret incorrect',
        404: 'No matching Threema ID could be found',
        500: 'Temporary internal server error occurred'
    }


# noinspection PyShadowingBuiltins
class KeyError(GatewayError):
    """
    A problem with a key occurred.
    """
    pass


class KeyServerError(KeyError, GatewayServerError):
    """
    The server has responded with an error code while fetching a
    public key.
    """
    status_description = {
        401: 'API identity or secret incorrect',
        404: 'No matching Threema ID could be found',
        500: 'Temporary internal server error occurred'
    }


class ReceptionCapabilitiesError(GatewayError):
    """
    An invalid reception capability has been returned.
    """
    pass


class ReceptionCapabilitiesServerError(
    ReceptionCapabilitiesError, GatewayServerError):
    """
    The server responded with an error code while fetching the reception
    capabilities of a Threema ID.
    """
    status_description = {
        401: 'API identity or secret incorrect',
        404: 'No matching Threema ID could be found',
        500: 'Temporary internal server error occurred'
    }


class MessageError(GatewayError):
    """
    Indicates that a message is invalid. The server has not been
    contacted, yet.
    """
    pass


class MessageServerError(MessageError, GatewayServerError):
    """
    The server has responded with an error code while sending a
    message.
    """
    status_description = {
        400: 'Recipient identity is invalid or the account is not setup for the '
             'requested mode',
        401: 'API identity or secret incorrect',
        402: 'Insufficient credits',
        404: 'Phone or email address could not be resolved to a Threema ID',
        413: 'Message too long',
        500: 'Temporary internal server error occurred'
    }


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
        'send_simple': 'https://msgapi.threema.ch/send_simple',
        'send_e2e': 'https://msgapi.threema.ch/send_e2e'
    }

    def __init__(self, id, secret, key=None, key_file=None):
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
            raise KeyError("Sender's private key not specified")
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
            raise KeyServerError(response)

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
            raise IDServerError(response)

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
            raise ReceptionCapabilitiesServerError(response)

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

    def _get(self, *args, **kwargs):
        """
        Wrapper for :func:`requests.get` that injects the connection's
        Threema ID and its secret.

        Return a :class:`requests.Response` instance.
        """
        kwargs.setdefault('params', {})
        kwargs['params'].setdefault('from', self.id)
        kwargs['params'].setdefault('secret', self.secret)
        return requests.get(*args, **kwargs)

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
        response = requests.post(url, data=data)
        if response.status_code == 200:
            return response.text
        else:
            raise MessageServerError(response)
