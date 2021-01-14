import subprocess

import pytest

from threema.gateway import ReceptionCapability
from threema.gateway import __version__ as _version
from threema.gateway import feature_level
from threema.gateway.key import Key


class TestCLI:
    @pytest.mark.asyncio
    async def test_invalid_command(self, cli):
        with pytest.raises(subprocess.CalledProcessError):
            await cli('meow')

    @pytest.mark.asyncio
    async def test_get_version(self, cli):
        output = await cli('version')
        assert 'Version: {}'.format(_version) in output
        assert 'Feature Level: {}'.format(feature_level) in output

    @pytest.mark.asyncio
    async def test_invalid_key(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli('encrypt', 'meow', 'meow', input='meow')
        assert 'Invalid key format' in exc_info.value.output
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'encrypt', pytest.msgapi.public, pytest.msgapi.private, input='meow')
        assert 'Invalid key type' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_encrypt_decrypt(self, cli):
        input = '私はガラスを食べられます。それは私を傷つけません。'
        output = await cli(
            'encrypt', pytest.msgapi.private, pytest.msgapi.public, input=input)
        nonce, data = output.splitlines()
        output = await cli(
            'decrypt', pytest.msgapi.private, pytest.msgapi.public, nonce, input=data)
        assert input in output

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_by_file(self, cli, private_key_file, public_key_file):
        input = '私はガラスを食べられます。それは私を傷つけません。'
        output = await cli(
            'encrypt', private_key_file, public_key_file, input=input)
        nonce, data = output.splitlines()
        output = await cli(
            'decrypt', private_key_file, public_key_file, nonce, input=data)
        assert input in output

    @pytest.mark.asyncio
    async def test_generate(self, cli, tmpdir):
        private_key_file = tmpdir.join('tmp_private_key')
        public_key_file = tmpdir.join('tmp_public_key')
        await cli('generate', str(private_key_file), str(public_key_file))
        private_key = Key.decode(private_key_file.read().strip(), Key.Type.private)
        public_key = Key.decode(public_key_file.read().strip(), Key.Type.public)
        assert private_key
        assert public_key

    @pytest.mark.asyncio
    async def test_hash_no_option(self, cli):
        with pytest.raises(subprocess.CalledProcessError):
            await cli('hash')

    @pytest.mark.asyncio
    async def test_hash_valid_email(self, cli):
        hash_ = '1ea093239cc5f0e1b6ec81b866265b921f26dc4033025410063309f4d1a8ee2c'
        output = await cli('hash', '-e', 'test@threema.ch')
        assert hash_ in output
        output = await cli('hash', '--email', 'test@threema.ch')
        assert hash_ in output

    @pytest.mark.asyncio
    async def test_hash_valid_phone_number(self, cli):
        hash_ = 'ad398f4d7ebe63c6550a486cc6e07f9baa09bd9d8b3d8cb9d9be106d35a7fdbc'
        output = await cli('hash', '-p', '41791234567')
        assert hash_ in output
        output = await cli('hash', '--phone', '41791234567')
        assert hash_ in output

    @pytest.mark.asyncio
    async def test_derive(self, cli):
        output = await cli('derive', pytest.msgapi.private)
        assert pytest.msgapi.public in output

    @pytest.mark.asyncio
    async def test_send_simple(self, cli):
        id_, secret = pytest.msgapi.id, pytest.msgapi.secret
        output = await cli('send_simple', 'ECHOECHO', id_, secret, input='Hello!')
        assert output

    @pytest.mark.asyncio
    async def test_send_e2e(self, cli, server):
        output_1 = await cli(
            'send_e2e', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, input='Hello!')
        assert output_1
        output_2 = await cli(
            'send_e2e', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, '-k', server.echoecho_encoded_key, input='Hello!')
        assert output_2
        assert output_1 == output_2

    @pytest.mark.asyncio
    async def test_send_image(self, cli, server):
        server.latest_blob_ids = []
        output_1 = await cli(
            'send_image', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg)
        assert output_1
        assert len(server.latest_blob_ids) == 1
        output_2 = await cli(
            'send_image', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg, '-k', server.echoecho_encoded_key)
        assert output_2
        assert output_1 == output_2
        assert len(server.latest_blob_ids) == 2

    @pytest.mark.asyncio
    async def test_send_video(self, cli, server):
        server.latest_blob_ids = []
        output_1 = await cli(
            'send_video', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_mp4, server.threema_jpg)
        assert output_1
        assert len(server.latest_blob_ids) == 2
        output_2 = await cli(
            'send_video', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_mp4, server.threema_jpg,
            '-k', server.echoecho_encoded_key)
        assert output_2
        assert output_1 == output_2
        assert len(server.latest_blob_ids) == 4
        output = await cli(
            'send_video', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_mp4, server.threema_jpg,
            '-d', '1337')
        assert output
        assert len(server.latest_blob_ids) == 6

    @pytest.mark.asyncio
    async def test_send_file(self, cli, server):
        server.latest_blob_ids = []
        output_1 = await cli(
            'send_file', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg)
        assert output_1
        assert len(server.latest_blob_ids) == 1
        output_2 = await cli(
            'send_file', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg, '-k', server.echoecho_encoded_key)
        assert output_2
        assert output_1 == output_2
        assert len(server.latest_blob_ids) == 2
        output = await cli(
            'send_file', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg, '-t', server.threema_jpg)
        assert output
        assert len(server.latest_blob_ids) == 4
        output = await cli(
            'send_file', 'ECHOECHO', pytest.msgapi.id, pytest.msgapi.secret,
            pytest.msgapi.private, server.threema_jpg, '-k', server.echoecho_encoded_key,
            '-t', server.threema_jpg)
        assert output
        assert len(server.latest_blob_ids) == 6

    @pytest.mark.asyncio
    async def test_lookup_no_option(self, cli):
        with pytest.raises(subprocess.CalledProcessError):
            await cli('lookup', pytest.msgapi.id, pytest.msgapi.secret)

    @pytest.mark.asyncio
    async def test_lookup_id_by_email(self, cli):
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret,
            '-e', 'echoecho@example.com')
        assert 'ECHOECHO' in output
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret,
            '--email', 'echoecho@example.com')
        assert 'ECHOECHO' in output

    @pytest.mark.asyncio
    async def test_lookup_id_by_phone(self, cli):
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret, '-p', '44123456789')
        assert 'ECHOECHO' in output
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret, '--phone', '44123456789')
        assert 'ECHOECHO' in output

    @pytest.mark.asyncio
    async def test_lookup_pk_by_id(self, cli, server):
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret, '-i', 'ECHOECHO')
        assert server.echoecho_encoded_key in output
        output = await cli(
            'lookup', pytest.msgapi.id, pytest.msgapi.secret, '--id', 'ECHOECHO')
        assert server.echoecho_encoded_key in output

    @pytest.mark.asyncio
    async def test_capabilities(self, cli):
        output = await cli(
            'capabilities', pytest.msgapi.id, pytest.msgapi.secret, 'ECHOECHO')
        capabilities = {
            ReceptionCapability.text,
            ReceptionCapability.image,
            ReceptionCapability.video,
            ReceptionCapability.file
        }
        assert all((capability.value in output for capability in capabilities))

    @pytest.mark.asyncio
    async def test_credits(self, cli):
        output = await cli('credits', pytest.msgapi.id, pytest.msgapi.secret)
        assert '100' in output
        output = await cli(
            'credits', pytest.msgapi.nocredit_id, pytest.msgapi.secret)
        assert '0' in output

    @pytest.mark.asyncio
    async def test_invalid_id(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await cli(
                'credits', pytest.msgapi.noexist_id, pytest.msgapi.secret)
        assert 'API identity or secret incorrect' in exc_info.value.output

    @pytest.mark.asyncio
    async def test_insufficient_credits(self, cli):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            id_, secret = pytest.msgapi.nocredit_id, pytest.msgapi.secret
            await cli('send_simple', 'ECHOECHO', id_, secret, input='!')
        assert 'Insufficient credits' in exc_info.value.output
