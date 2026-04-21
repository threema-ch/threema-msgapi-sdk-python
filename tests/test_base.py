import pytest
from packaging.version import Version
import libnacl
import libnacl.public
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

    def test_invalid_pk(self):
        all_zero_pk = libnacl.public.PublicKey(bytes(libnacl.crypto_box_PUBLICKEYBYTES))
        key_pair = key.Key.generate_secret_key, all_zero_pk
        data_in = b'meow'
        nonce = b'0' * 24
        with pytest.raises(libnacl.CryptError) as exc_info:
            e2e._pk_encrypt(key_pair, data_in, nonce=nonce)
        assert 'Invalid public key' in str(exc_info.value)

        with pytest.raises(libnacl.CryptError) as exc_info:
            e2e._pk_decrypt(key_pair, nonce, bytes(5))
        assert 'Invalid public key' in str(exc_info.value)

    @pytest.mark.skipif(Version(libnacl.sodium_version_string().decode("ascii")) < Version("1.0.7"),
                        reason="no zero-result check on X25519 in this version of libsodium")
    def test_contributory(self):
        all_zero_pk = libnacl.public.PublicKey(bytes(libnacl.crypto_box_PUBLICKEYBYTES))
        alice_sk, _ = key.Key.generate_pair()
        with pytest.raises(libnacl.CryptError) as exc_info:
            alice_box = libnacl.public.Box(alice_sk, all_zero_pk)
        assert 'Unable to compute shared key' in str(exc_info)

