"""
The tests provided in this module have been tested for compliance with
the Threema Gateway server. Obviously, the simulated server does not
completely mimic the behaviour of the Gateway server.
"""
import binascii
import asyncio

import pytest

from threema.gateway.exception import *
from threema.gateway import simple, e2e, ReceptionCapability

server = pytest.msgapi.Server()


class RawMessage(e2e.Message):
    def __init__(self, connection, nonce=None, message=None, **kwargs):
        super().__init__(connection, e2e.Message.Type.text_message, **kwargs)
        self.nonce = nonce
        self.message = message

    @asyncio.coroutine
    def pack(self, writer):
        raise NotImplementedError

    @classmethod
    @asyncio.coroutine
    def unpack(cls, connection, parameters, key_pair, reader):
        raise NotImplementedError

    @asyncio.coroutine
    def send(self):
        """
        Send the raw message

        Return the ID of the message.
        """
        # Send message
        return (yield from self._connection.send_e2e(**{
            'to': self.to_id,
            'nonce': binascii.hexlify(self.nonce).decode(),
            'box': binascii.hexlify(self.message).decode()
        }))


@asyncio.coroutine
def get_latest_blob_ids(connection):
    blobs = [(yield from (yield from connection.download(blob_id)).read())
             for blob_id in server.latest_blob_ids]
    return blobs


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
    def test_valid_id(self, connection):
        key = yield from connection.get_public_key('ECHOECHO')
        assert key.hex_pk() == server.echoecho_key


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
    def test_just_ok(self, connection):
        blob_id = yield from connection.upload(bytes(20 * (2**20)))
        assert len(blob_id) == 16
        # Note: Remove big blob because further tests may hang
        del server.blobs[blob_id]

    @pytest.mark.asyncio
    def test_too_big(self, connection):
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
        assert len((yield from connection.upload(b'\x01'))) == 16


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
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=invalid_connection,
                to_id='ECHOECHO',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_insufficient_credits(self, nocredit_connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=nocredit_connection,
                to_id='ECHOECHO',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 402

    @pytest.mark.asyncio
    def test_message_too_long(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from RawMessage(
                connection=connection,
                to_id='ECHOECHO',
                nonce=b'0' * 24,
                message=b'1' * 4001
            ).send()
        assert exc_info.value.status == 413

    @pytest.mark.asyncio
    def test_unknown_id(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=connection,
                to_id='00000000',
                key=server.echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 400

    @pytest.mark.asyncio
    def test_raw(self, connection):
        id_ = yield from RawMessage(
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
    def test_via_id_and_key(self, connection):
        id_ = yield from e2e.TextMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            text='Hello'
        ).send()
        assert id_ == '1' * 16

    @pytest.mark.asyncio
    def test_image(self, connection):
        server.latest_blob_ids = []
        id_ = yield from e2e.ImageMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            image_path=server.threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(server.latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(connection)))

    @pytest.mark.asyncio
    def test_file(self, connection):
        server.latest_blob_ids = []
        id_ = yield from e2e.FileMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=server.echoecho_encoded_key,
            file_path=server.threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(server.latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(connection)))

    @pytest.mark.asyncio
    def test_file_with_thumbnail(self, connection):
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
        assert all((yield from get_latest_blob_ids(connection)))
