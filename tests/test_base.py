import libnacl
import pytest

from threema.gateway import (
    e2e,
    key,
)


class TestCrypto:
    def test_incorrect_nonce(self):
        key_pair = key.Key.generate_pair()
        data_in = b'meow'
        nonce = b'0' * 23
        with pytest.raises(ValueError) as exc_info:
            e2e._pk_encrypt(key_pair, data_in, nonce=nonce)
        assert 'Invalid nonce size' in str(exc_info.value)

    def test_incorrect_ciphertext(self):
        key_pair = key.Key.generate_pair()
        data_in = b'meow'
        nonce = b'0' * 24
        with pytest.raises(libnacl.CryptError) as exc_info:
            _, data_encrypted = e2e._pk_encrypt(key_pair, data_in, nonce=nonce)
            e2e._pk_decrypt(key_pair, nonce, data_encrypted + b'0')
        assert 'decrypt' in str(exc_info.value)

    def test_valid(self):
        key_pair = key.Key.generate_pair()
        data_in = b'meow'
        nonce = b'0' * 24
        _, data_encrypted = e2e._pk_encrypt(key_pair, data_in, nonce=nonce)
        data_out = e2e._pk_decrypt(key_pair, nonce, data_encrypted)
        assert data_in == data_out
