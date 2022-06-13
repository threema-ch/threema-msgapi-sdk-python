"""
Contains functions to decode, encode and generate keys.
"""
import enum
import hashlib
import hmac

import libnacl.encode
import libnacl.public
import libnacl.secret

from .exception import GatewayKeyError

__all__ = (
    'HMAC',
    'Key',
)


class HMAC:
    """
    A collection of HMAC functions used for the gateway service.
    """
    keys = {
        'email': b'\x30\xa5\x50\x0f\xed\x97\x01\xfa\x6d\xef\xdb\x61\x08\x41\x90\x0f'
                 b'\xeb\xb8\xe4\x30\x88\x1f\x7a\xd8\x16\x82\x62\x64\xec\x09\xba\xd7',
        'phone': b'\x85\xad\xf8\x22\x69\x53\xf3\xd9\x6c\xfd\x5d\x09\xbf\x29\x55\x5e'
                 b'\xb9\x55\xfc\xd8\xaa\x5e\xc4\xf9\xfc\xd8\x69\xe2\x58\x37\x07\x23'
    }

    @staticmethod
    def hash(message, hash_type):
        """
        Generate the hash for a message type.

        Arguments:
            - `message`: A message.
            - `hash_type`: `email` or `phone`.

        Return a :class:`hmac.HMAC` instance.
        """
        return hmac.new(HMAC.keys[hash_type], message.encode('ascii'), hashlib.sha256)


class Key:
    """
    Encode or decode a key.
    """
    separator = ':'

    @enum.unique
    class Type(enum.Enum):
        """
        The type of a key.
        """
        private = 'private'
        public = 'public'

    @staticmethod
    def decode(encoded_key, expected_type):
        """
        Decode a key and check its type if required.

        Arguments:
            - `encoded_key`: The encoded key.
            - `expected_type`: One of the types of :class:`Key.Type`.

        Return the key as an :class:`libnacl.public.SecretKey` or
        :class:`libnacl.public.PublicKey` instance.
        """
        # Split key
        try:
            type_, key = encoded_key.split(Key.separator)
        except ValueError as exc:
            raise GatewayKeyError('Invalid key format') from exc
        type_ = Key.Type(type_)

        # Check type
        if type_ != expected_type:
            raise GatewayKeyError('Invalid key type: {}, expected: {}'.format(
                type_, expected_type
            ))

        # De-hexlify
        key = libnacl.encode.hex_decode(key)

        # Convert to SecretKey or PublicKey
        if type_ == Key.Type.private:
            key = libnacl.public.SecretKey(key)
        elif type_ == Key.Type.public:
            key = libnacl.public.PublicKey(key)

        return key

    @staticmethod
    def encode(libnacl_key):
        """
        Encode a key.

        Arguments:
            - `libnacl_key`: An instance of either a
              :class:`libnacl.public.SecretKey` or a
              :class:`libnacl.public.PublicKey`.

        Return the encoded key.
        """
        # Detect key type and hexlify
        if isinstance(libnacl_key, libnacl.public.SecretKey):
            type_ = Key.Type.private
            key = libnacl_key.hex_sk()
        elif isinstance(libnacl_key, libnacl.public.PublicKey):
            type_ = Key.Type.public
            key = libnacl.encode.hex_encode(libnacl_key.pk)
        else:
            raise GatewayKeyError('Unknown key type: {}'.format(libnacl_key))

        # Encode key
        return Key.separator.join((type_.value, key.decode('utf-8')))

    @staticmethod
    def generate_pair():
        """
        Generate a new key pair.

        Return the key pair as a tuple of a
        :class:`libnacl.public.SecretKey` instance and a
        :class:`libnacl.public.PublicKey` instance.
        """
        private_key = libnacl.public.SecretKey()
        public_key = libnacl.public.PublicKey(private_key.pk)
        return private_key, public_key

    @staticmethod
    def generate_secret_key():
        """
        Generate a new secret key box.

        Return a tuple of the key's :class:`bytes` and hex-encoded
        representation.
        """
        box = libnacl.secret.SecretBox()
        return box.sk, box.hex_sk()

    @staticmethod
    def derive_public(private_key):
        """
        Derive a public key from a class:`libnacl.public.SecretKey`
        instance.

        Arguments:
            - `private_key`: A class:`libnacl.public.SecretKey`
              instance.

        Return the :class:`libnacl.public.PublicKey` instance.
        """
        return libnacl.public.PublicKey(private_key.pk)
