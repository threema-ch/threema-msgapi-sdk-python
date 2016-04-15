"""
The tests provided in this module have been tested for compliance with
the Threema Gateway server. Obviously, the simulated server does not
completely mimic the behaviour of the Gateway server.
"""
import binascii
import hashlib
import os
import asyncio

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher

from threema.gateway.exception import *
from threema.gateway import simple, e2e, ReceptionCapability


_res_path = os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir, 'res'))
_threema_jpg = os.path.join(_res_path, 'threema.jpg')
_echoecho_key = b'4a6a1b34dcef15d43cb74de2fd36091be99fbbaf126d099d47d83d919712c72b'
_echoecho_encoded_key = 'public:' + _echoecho_key.decode()
_blobs = {}
_latest_blob_ids = []


@asyncio.coroutine
def pubkeys(request):
    key = request.match_info['key']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif len(key) != 8:
        return web.Response(status=404)
    elif key == 'ECHOECHO':
        return web.Response(body=_echoecho_key)
    return web.Response(status=404)


@asyncio.coroutine
def lookup_phone(request):
    phone = request.match_info['phone']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif not phone.isdigit():
        return web.Response(status=404)
    elif phone == '44123456789':
        return web.Response(body=b'ECHOECHO')
    return web.Response(status=404)


@asyncio.coroutine
def lookup_phone_hash(request):
    phone_hash = request.match_info['phone_hash']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif len(phone_hash) % 2 != 0:
        # Note: This status code might not be intended and may change in the future
        return web.Response(status=500)
    elif len(phone_hash) != 64:
        return web.Response(status=400)
    elif phone_hash == '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214c':
        return web.Response(body=b'ECHOECHO')
    return web.Response(status=404)


@asyncio.coroutine
def lookup_email(request):
    email = request.match_info['email']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif email == 'echoecho@example.com':
        return web.Response(body=b'ECHOECHO')
    return web.Response(status=404)


@asyncio.coroutine
def lookup_email_hash(request):
    email_hash = request.match_info['email_hash']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif len(email_hash) % 2 != 0:
        # Note: This status code might not be intended and may change in the future
        return web.Response(status=500)
    elif len(email_hash) != 64:
        return web.Response(status=400)
    elif email_hash == '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e2':
        return web.Response(body=b'ECHOECHO')
    return web.Response(status=404)


@asyncio.coroutine
def capabilities(request):
    id_ = request.match_info['id']
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    elif id_ == 'ECHOECHO':
        return web.Response(body=b'text,image,video,file')
    return web.Response(status=404)


@asyncio.coroutine
def credits(request):
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)
    return web.Response(body=b'100')


@asyncio.coroutine
def send_simple(request):
    post = (yield from request.post())

    # Check API identity
    if (post['from'], post['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)

    # Get ID from to, email or phone
    if 'to' in post:
        id_ = post['to']
    elif post.get('email', None) == 'echoecho@example.com':
        id_ = 'ECHOECHO'
    elif post.get('phone', None) == '44123456789':
        id_ = 'ECHOECHO'
    else:
        return web.Response(status=404)

    # Process
    text = post['text']
    if post['from'] == pytest.msgapi.nocredit_id:
        return web.Response(status=402)
    elif id_ != 'ECHOECHO':
        return web.Response(status=400)
    elif len(text) > 3500:
        return web.Response(status=413)
    return web.Response(body=b'0' * 16)


@asyncio.coroutine
def send_e2e(request):
    post = (yield from request.post())

    # Check API identity
    if (post['from'], post['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)

    # Get ID, nonce and box
    id_ = post['to']
    nonce, box = binascii.unhexlify(post['nonce']), binascii.unhexlify(post['box'])

    # Process
    if post['from'] == pytest.msgapi.nocredit_id:
        return web.Response(status=402)
    elif id_ != 'ECHOECHO':
        return web.Response(status=400)
    elif len(nonce) != 24:
        # Note: This status code might not be intended and may change in the future
        return web.Response(status=400)
    elif len(box) > 4000:
        return web.Response(status=413)
    return web.Response(body=b'1' * 16)


@asyncio.coroutine
def upload_blob(request):
    try:
        data = (yield from request.post())

        # Check API identity
        api_identity = (request.GET['from'], request.GET['secret'])
        if api_identity not in pytest.msgapi.api_identities:
            return web.Response(status=401)
    except KeyError:
        return web.Response(status=401)

    try:
        # Get blob
        blob = data['blob'].file.read()
    except KeyError:
        # Note: This status code might not be intended and may change in the future
        return web.Response(status=500)

    # Generate ID
    blob_id = hashlib.md5(blob).hexdigest()[16:]

    # Process
    if request.GET['from'] == pytest.msgapi.nocredit_id:
        return web.Response(status=402)
    elif len(blob) == 0:
        return web.Response(status=400)
    elif len(blob) > 20 * (2**20):
        return web.Response(status=413)

    # Store blob and return
    _blobs[blob_id] = blob
    _latest_blob_ids.append(blob_id)
    return web.Response(body=blob_id.encode())


@asyncio.coroutine
def download_blob(request):
    blob_id = request.match_info['blob_id']

    # Check API identity
    if (request.GET['from'], request.GET['secret']) not in pytest.msgapi.api_identities:
        return web.Response(status=401)

    # Get blob
    try:
        blob = _blobs[blob_id]
    except KeyError:
        return web.Response(status=404)
    else:
        return web.Response(
            body=blob,
            content_type='application/octet-stream'
        )


router = UrlDispatcher()
router.add_route('GET', '/pubkeys/{key}', pubkeys)
router.add_route('GET', '/lookup/phone/{phone}', lookup_phone)
router.add_route('GET', '/lookup/phone_hash/{phone_hash}', lookup_phone_hash)
router.add_route('GET', '/lookup/email/{email}', lookup_email)
router.add_route('GET', '/lookup/email_hash/{email_hash}', lookup_email_hash)
router.add_route('GET', '/capabilities/{id}', capabilities)
router.add_route('GET', '/credits', credits)
router.add_route('POST', '/send_simple', send_simple)
router.add_route('POST', '/send_e2e', send_e2e)
router.add_route('POST', '/upload_blob', upload_blob)
router.add_route('GET', '/blobs/{blob_id}', download_blob)


class RawMessage(e2e.Message):
    def __init__(self, connection, nonce=None, message=None, **kwargs):
        super().__init__(connection, e2e.Message.Type.text_message, **kwargs)
        self.nonce = nonce
        self.message = message

    @asyncio.coroutine
    def _pack(self, writer):
        raise NotImplementedError

    @classmethod
    @asyncio.coroutine
    def _unpack(cls, connection, parameters, key_pair, reader):
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
             for blob_id in _latest_blob_ids]
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
        assert key.hex_pk() == _echoecho_key


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
        del _blobs[blob_id]

    @pytest.mark.asyncio
    def test_too_big(self, connection):
        with pytest.raises(BlobServerError) as exc_info:
            blob_id = yield from connection.upload(bytes((20 * (2**20)) + 1))
            # Note: Remove big blob because further tests may hang
            del _blobs[blob_id]
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
                key=_echoecho_encoded_key,
                text='Hello'
            ).send()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    def test_insufficient_credits(self, nocredit_connection):
        with pytest.raises(MessageServerError) as exc_info:
            yield from e2e.TextMessage(
                connection=nocredit_connection,
                to_id='ECHOECHO',
                key=_echoecho_encoded_key,
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
                key=_echoecho_encoded_key,
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
            key=_echoecho_encoded_key,
            text='Hello'
        ).send()
        assert id_ == '1' * 16

    @pytest.mark.asyncio
    def test_image(self, connection):
        global _latest_blob_ids
        _latest_blob_ids = []
        id_ = yield from e2e.ImageMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=_echoecho_encoded_key,
            image_path=_threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(_latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(connection)))

    @pytest.mark.asyncio
    def test_file(self, connection):
        global _latest_blob_ids
        _latest_blob_ids = []
        id_ = yield from e2e.FileMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=_echoecho_encoded_key,
            file_path=_threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(_latest_blob_ids) == 1
        assert all((yield from get_latest_blob_ids(connection)))

    @pytest.mark.asyncio
    def test_file_with_thumbnail(self, connection):
        global _latest_blob_ids
        _latest_blob_ids = []
        id_ = yield from e2e.FileMessage(
            connection=connection,
            to_id='ECHOECHO',
            key=_echoecho_encoded_key,
            file_path=_threema_jpg,
            thumbnail_path=_threema_jpg
        ).send()
        assert id_ == '1' * 16
        assert len(_latest_blob_ids) == 2
        assert all((yield from get_latest_blob_ids(connection)))
