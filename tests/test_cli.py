import subprocess

import pytest

from threema.gateway import __version__ as _version
from threema.gateway import feature_level
from threema.gateway.key import Key

server = pytest.msgapi.Server()


class TestCLI:
    @pytest.mark.asyncio
    def test_get_version(self, cli):
        output = yield from cli('version')
        assert 'Version: {}'.format(_version) in output
        assert 'Feature Level: {}'.format(feature_level) in output

    @pytest.mark.asyncio
    def test_encrypt_decrypt(self, cli):
        input = '私はガラスを食べられます。それは私を傷つけません。'
        output = yield from cli('encrypt', pytest.msgapi.private, pytest.msgapi.public,
                                input=input)
        nonce, data = output.splitlines()
        output =yield from  cli('decrypt', pytest.msgapi.private, pytest.msgapi.public,
                                nonce, input=data)
        assert input in output

    @pytest.mark.asyncio
    def test_encrypt_decrypt_by_file(self, cli, private_key_file, public_key_file):
        input = '私はガラスを食べられます。それは私を傷つけません。'
        output = yield from cli('encrypt', private_key_file, public_key_file,
                                input=input)
        nonce, data = output.splitlines()
        output = yield from cli('decrypt', private_key_file, public_key_file, nonce,
                                input=data)
        assert input in output

    @pytest.mark.asyncio
    def test_generate(self, cli, tmpdir):
        private_key_file = tmpdir.join('tmp_private_key')
        public_key_file = tmpdir.join('tmp_public_key')
        yield from cli('generate', str(private_key_file), str(public_key_file))
        private_key = Key.decode(private_key_file.read().strip(), Key.Type.private)
        public_key = Key.decode(public_key_file.read().strip(), Key.Type.public)
        assert private_key
        assert public_key

    @pytest.mark.asyncio
    def test_hash_no_option(self, cli):
        with pytest.raises(subprocess.CalledProcessError):
            yield from cli('hash')

    @pytest.mark.asyncio
    def test_hash_valid_email(self, cli):
        hash_ = '1ea093239cc5f0e1b6ec81b866265b921f26dc4033025410063309f4d1a8ee2c'
        output = yield from cli('hash', '-e', 'test@threema.ch')
        assert hash_ in output
        output = yield from cli('hash', '--email', 'test@threema.ch')
        assert hash_ in output

    @pytest.mark.asyncio
    def test_hash_valid_phone_number(self, cli):
        hash_ = 'ad398f4d7ebe63c6550a486cc6e07f9baa09bd9d8b3d8cb9d9be106d35a7fdbc'
        output = yield from cli('hash', '-p', '41791234567')
        assert hash_ in output
        output = yield from cli('hash', '--phone', '41791234567')
        assert hash_ in output

    @pytest.mark.asyncio
    def test_derive(self, cli):
        output = yield from cli('derive', pytest.msgapi.private)
        assert pytest.msgapi.public in output

    @pytest.mark.asyncio
    def test_send_simple(self, cli):
        id_, secret = pytest.msgapi.id, pytest.msgapi.secret
        output = yield from cli('send_simple', 'ECHOECHO', id_, secret, input='Hello!')
        assert output
