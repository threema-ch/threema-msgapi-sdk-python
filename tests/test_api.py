"""
The tests provided in this module have been tested for compliance with
the Threema Gateway server. Obviously, the simulated server does not
completely mimic the behaviour of the Gateway server.
"""
import asyncio

import pytest

from threema.gateway import (
    ReceptionCapability,
    e2e,
    simple,
)
from threema.gateway.exception import (
    BlobServerError,
    CreditsServerError,
    IDServerError,
    KeyServerError,
    MessageServerError,
    ReceptionCapabilitiesServerError,
)


@asyncio.coroutine
def download_blob(connection, blob_id):
    response = yield from connection.download(blob_id)
    return response.read()


@asyncio.coroutine
def get_latest_blob_ids(server, connection):
    return asyncio.gather(*[download_blob(connection, blob_id)
                            for blob_id in server.latest_blob_ids])


class TestLookupPublicKey:
    @pytest.mark.asyncio
    def test_invalid_identitiy(self, invalid_connection):
        with pytest.raises(KeyServerError) as exc_info:
            yield from invalid_connection.get_public_key('ECHOECHO')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_invalid_length(self, connection):
        with pytest.raises(KeyServerError) as exc_info:
            yield from connection.get_public_key('TEST')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_unknown_id(self, connection):
        with pytest.raises(KeyServerError) as exc_info:
            yield from connection.get_public_key('00000000')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_id(self, connection, server):
        key = yield from connection.get_public_key('ECHOECHO')
        assert key.hex_pk() == server.echoecho_key

    @pytest.mark.asyncio
    @asyncio.coroutine
    def test_cache_expiration(self, connection, server):
        connection.get_public_key.cache_clear()
        connection.get_public_key.cache.expiration = 0.05
        for _ in range(10):
            yield from connection.get_public_key('ECHOECHO')
        cache_info = connection.get_public_key.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 9
        yield from asyncio.sleep(0.2)
        yield from connection.get_public_key('ECHOECHO')
        cache_info = connection.get_public_key.cache_info()
        # For some reason, the cache is not always being cleared and I don't want
        # Travis to fail all the time
        assert cache_info.misses == 1 or cache_info.misses == 2

    @pytest.mark.asyncio
    def test_cache_hits(self, connection, server):
        connection.get_public_key.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_id(connection, server)
        cache_info = connection.get_public_key.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestLookupIDByPhone:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from invalid_connection.get_id(phone='44123456789')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_unknown_phone(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone='44987654321')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_invalid_phone(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone='-12537825318')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_phone(self, connection):
        id_ = yield from connection.get_id(phone='44123456789')
        assert id_ == 'ECHOECHO'

    @pytest.mark.asyncio
    def test_cache_hits(self, connection):
        connection.get_id.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_phone(connection)
        cache_info = connection.get_id.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestLookupIDByPhoneHash:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from invalid_connection.get_id(phone_hash='invalid_hash')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_invalid_length(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af14421'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone_hash=phone_hash)
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_odd_length(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone_hash=phone_hash)
        # Note: This status code might not be intended and may change in the future
        assert exc_info.value.status == 500

    @pytest.mark.asyncio
    def test_invalid_phone_hash(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone_hash='1234')
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_unknown_phone_hash(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214a'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(phone_hash=phone_hash)
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_phone_hash(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214c'
        id_ = yield from connection.get_id(phone_hash=phone_hash)
        assert id_ == 'ECHOECHO'

    @pytest.mark.asyncio
    def test_cache_hits(self, connection):
        connection.get_id.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_phone_hash(connection)
        cache_info = connection.get_id.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestLookupIDByEmail:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from invalid_connection.get_id(email='echoecho@example.com')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_unknown_email(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email='somemail@example.com')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_invalid_email(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email='invalid')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_email(self, connection):
        id_ = yield from connection.get_id(email='echoecho@example.com')
        assert id_ == 'ECHOECHO'

    @pytest.mark.asyncio
    def test_cache_hits(self, connection):
        connection.get_id.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_email(connection)
        cache_info = connection.get_id.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestLookupIDByEmailHash:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from invalid_connection.get_id(email_hash='invalid_hash')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_invalid_length(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email_hash=email_hash)
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_odd_length(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email_hash=email_hash)
        # Note: This status code might not be intended and may change in the future
        assert exc_info.value.status == 500

    @pytest.mark.asyncio
    def test_invalid_email_hash(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email_hash='1234')
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_unknown_email_hash(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e1'
        with pytest.raises(IDServerError) as exc_info:
            yield from connection.get_id(email_hash=email_hash)
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_email_hash(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e2'
        id_ = yield from connection.get_id(email_hash=email_hash)
        assert id_ == 'ECHOECHO'

    @pytest.mark.asyncio
    def test_cache_hits(self, connection):
        connection.get_id.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_email_hash(connection)
        cache_info = connection.get_id.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestReceptionCapabilities:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            yield from invalid_connection.get_reception_capabilities('ECHOECHO')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_invalid_length(self, connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            yield from connection.get_reception_capabilities('TEST')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_unknown_id(self, connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            yield from connection.get_reception_capabilities('00000000')
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_valid_id(self, connection):
        key = yield from connection.get_reception_capabilities('ECHOECHO')
        assert key == {
            ReceptionCapability.text,
            ReceptionCapability.image,
            ReceptionCapability.video,
            ReceptionCapability.file
        }

    @pytest.mark.asyncio
    def test_cache_hits(self, connection):
        connection.get_reception_capabilities.cache_clear()
        for _ in range(1000):
            yield from self.test_valid_id(connection)
        cache_info = connection.get_reception_capabilities.cache_info()
        assert cache_info.misses == 1
        assert cache_info.hits == 999


class TestCredits:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(CreditsServerError) as exc_info:
            yield from invalid_connection.get_credits()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_valid(self, connection):
        assert (yield from connection.get_credits()) == 100


class TestUploadBlob:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(BlobServerError) as exc_info:
            yield from invalid_connection.upload(b'\x01')
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_insufficient_credits(self, nocredit_connection):
        with pytest.raises(BlobServerError) as exc_info:
            yield from nocredit_connection.upload(b'\x01')
        assert exc_info.value.status == 402

    @pytest.mark.asyncio
    def test_just_ok(self, connection, server):
        blob_id = yield from connection.upload(bytes(20 * (2**20)))
        assert len(blob_id) == 32
        # Note: Remove big blob because further tests may hang
        del server.blobs[blob_id]

    @pytest.mark.asyncio
    def test_too_big(self, connection, server):
        with pytest.raises(BlobServerError) as exc_info:
            blob_id = yield from connection.upload(bytes((20 * (2**20)) + 1))
            # Note: Remove big blob because further tests may hang
            del server.blobs[blob_id]
        assert exc_info.value.status == 413

    @pytest.mark.asyncio
    def test_zero(self, connection):
        with pytest.raises(BlobServerError) as exc_info:
            yield from connection.upload(b'')
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_file(self, connection):
        assert len((yield from connection.upload(b'\x01'))) == 32


class TestDownloadBlob:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection, blob_id):
        with pytest.raises(BlobServerError) as exc_info:
            yield from (yield from invalid_connection.download(blob_id)).read()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_invalid_id(self, connection):
        with pytest.raises(BlobServerError) as exc_info:
            yield from (yield from connection.download('f' * 15)).read()
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_unknown_id(self, connection):
        with pytest.raises(BlobServerError) as exc_info:
            yield from (yield from connection.download('f' * 16)).read()
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_file(self, connection, blob_id, blob):
        response = yield from connection.download(blob_id)
        assert (yield from response.read()) == blob

    @pytest.mark.asyncio
    def test_no_credits(self, nocredit_connection, blob_id, blob):
        response = yield from nocredit_connection.download(blob_id)
        assert (yield from response.read()) == blob


class TestSendSimple:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=invalid_connection,
                to_id='ECHOECHO',
                text='Hello'
            ).send()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_insufficient_credits(self, nocredit_connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=nocredit_connection,
                to_id='ECHOECHO',
                text='Hello'
            ).send()
        assert exc_info.value.status == 402

    @pytest.mark.asyncio
    def test_message_too_long(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=connection,
                to_id='ECHOECHO',
                text='0' * 3501
            ).send()
        assert exc_info.value.status == 413

    @pytest.mark.asyncio
    def test_unknown_id(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=connection,
                to_id='00000000',
                text='Hello'
            ).send()
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_unknown_email(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=connection,
                email='somemail@example.com',
                text='Hello'
            ).send()
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_unknown_phone(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from simple.TextMessage(
                connection=connection,
                phone='44987654321',
                text='Hello'
            ).send()
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    def test_via_id(self, connection):
        id_ = yield from simple.TextMessage(
            connection=connection,
            to_id='ECHOECHO',
            text='0' * 3500
        ).send()
        assert id_ == '0' * 16

    @pytest.mark.asyncio
    def test_via_email(self, connection):
        id_ = yield from simple.TextMessage(
            connection=connection,
            email='echoecho@example.com',
            text='Hello'
        ).send()
        assert id_ == '0' * 16

    @pytest.mark.asyncio
    def test_via_phone(self, connection):
        id_ = yield from simple.TextMessage(
            connection=connection,
            phone='44123456789',
            text='Hello'
        ).send()
        assert id_ == '0' * 16


class TestSendE2E:
    @pytest.mark.asyncio
    def test_invalid_identity(self, invalid_connection, server):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=invalid_connection,
                to_id='ECHOECHO',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_insufficient_credits(self, nocredit_connection, server):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=nocredit_connection,
                to_id='ECHOECHO',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 402

    @pytest.mark.asyncio
    def test_message_too_long(self, connection, raw_message):
        with pytest.raises(MessageServerError) as exc_info:
            yield from raw_message(
                connection=connection,
                to_id='ECHOECHO',
                nonce=b'0' * 24,
                message=b'1' * 4001
            ).send()
        assert exc_info.value.status == 413

    @pytest.mark.asyncio
    def test_unknown_id(self, connection, server):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=connection,
                to_id='00000000',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_raw(self, connection, raw_message):
        id_ = yield from raw_message(
            connection=connection,
            to_id='ECHOECHO',
            nonce=b'0' * 24,
            message=b'1' * 4000
        ).send()
        assert id_ == '1' * 16

    @pytest.mark.asyncio
    def test_via_id(self, connection):
        id_ = yield from e2e.TextMessage(
            connection=connection,
            to_id='ECHOECHO',
            text='Hello'
        ).send()
        assert id_ == '1' * 16

    @pytest.mark.asyncio
    def test_via_id_and_key(self, connection, server):
        id_ = yield from e2e.TextMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            text='Hello'
        ).send()
        assert id_ == '1' * 16

    @pytest.mark.asyncio
    def test_image(self, connection, server):
        server.latest_blob_ids = []
        id_ = yield from e2e.ImageMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            image_path=server.threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(server.latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(server, connection)))

    @pytest.mark.asyncio
    def test_file(self, connection, server):
        server.latest_blob_ids = []
        id_ = yield from e2e.FileMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            file_path=server.threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(server.latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(server, connection)))

    @pytest.mark.asyncio
    def test_file_with_thumbnail(self, connection, server):
        server.latest_blob_ids = []
        id_ = yield from e2e.FileMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            file_path=server.threema_jpg,
            thumbnail_path=server.threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(server.latest_blob_ids) == 2
        assert all((yield from get_latest_blob_ids(server, connection)))
