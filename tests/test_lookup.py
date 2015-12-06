"""
The tests provided in this module have been tested for compliance with
the Threema Gateway server. Obviously, the simulated server does not
completely mimic the behaviour of the Gateway server.
"""
import asyncio

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher

from threema.gateway.exception import *
from threema.gateway import simple, ReceptionCapability


_echoecho_key = b'4a6a1b34dcef15d43cb74de2fd36091be99fbbaf126d099d47d83d919712c72b'


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
        return web.Response(body=b'text,image,video')
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


router = UrlDispatcher()
router.add_route('GET', '/pubkeys/{key}', pubkeys)
router.add_route('GET', '/lookup/phone/{phone}', lookup_phone)
router.add_route('GET', '/lookup/phone_hash/{phone_hash}', lookup_phone_hash)
router.add_route('GET', '/lookup/email/{email}', lookup_email)
router.add_route('GET', '/lookup/email_hash/{email_hash}', lookup_email_hash)
router.add_route('GET', '/capabilities/{id}', capabilities)
router.add_route('GET', '/credits', credits)
router.add_route('POST', '/send_simple', send_simple)


class TestLookupPublicKey:
    def test_invalid_identitiy(self, invalid_connection):
        with pytest.raises(KeyServerError) as exc_info:
            invalid_connection.get_public_key('ECHOECHO')
        assert exc_info.value.response.status_code == 401

    def test_invalid_length(self, connection):
        with pytest.raises(KeyServerError) as exc_info:
            connection.get_public_key('TEST')
        assert exc_info.value.response.status_code == 404

    def test_unknown_id(self, connection):
        with pytest.raises(KeyServerError) as exc_info:
            connection.get_public_key('00000000')
        assert exc_info.value.response.status_code == 404

    def test_valid_id(self, connection):
        key = connection.get_public_key('ECHOECHO')
        assert key.hex_pk() == _echoecho_key


class TestLookupIDByPhone:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            invalid_connection.get_id(phone='44123456789')
        assert exc_info.value.response.status_code == 401

    def test_unknown_phone(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone='44987654321')
        assert exc_info.value.response.status_code == 404

    def test_invalid_phone(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone='-12537825318')
        assert exc_info.value.response.status_code == 404

    def test_valid_phone(self, connection):
        id_ = connection.get_id(phone='44123456789')
        assert id_ == 'ECHOECHO'


class TestLookupIDByPhoneHash:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            invalid_connection.get_id(phone_hash='invalid_hash')
        assert exc_info.value.response.status_code == 401

    def test_invalid_length(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af14421'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone_hash=phone_hash)
        assert exc_info.value.response.status_code == 400

    def test_odd_length(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone_hash=phone_hash)
        # Note: This status code might not be intended and may change in the future
        assert exc_info.value.response.status_code == 500

    def test_invalid_phone_hash(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone_hash='1234')
        assert exc_info.value.response.status_code == 400

    def test_unknown_phone_hash(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214a'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(phone_hash=phone_hash)
        assert exc_info.value.response.status_code == 404

    def test_valid_phone_hash(self, connection):
        phone_hash = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214c'
        id_ = connection.get_id(phone_hash=phone_hash)
        assert id_ == 'ECHOECHO'


class TestLookupIDByEmail:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            invalid_connection.get_id(email='echoecho@example.com')
        assert exc_info.value.response.status_code == 401

    def test_unknown_email(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email='somemail@example.com')
        assert exc_info.value.response.status_code == 404

    def test_invalid_email(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email='invalid')
        assert exc_info.value.response.status_code == 404

    def test_valid_email(self, connection):
        id_ = connection.get_id(email='echoecho@example.com')
        assert id_ == 'ECHOECHO'


class TestLookupIDByEmailHash:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(IDServerError) as exc_info:
            invalid_connection.get_id(email_hash='invalid_hash')
        assert exc_info.value.response.status_code == 401

    def test_invalid_length(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email_hash=email_hash)
        assert exc_info.value.response.status_code == 400

    def test_odd_length(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email_hash=email_hash)
        # Note: This status code might not be intended and may change in the future
        assert exc_info.value.response.status_code == 500

    def test_invalid_email_hash(self, connection):
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email_hash='1234')
        assert exc_info.value.response.status_code == 400

    def test_unknown_email_hash(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e1'
        with pytest.raises(IDServerError) as exc_info:
            connection.get_id(email_hash=email_hash)
        assert exc_info.value.response.status_code == 404

    def test_valid_email_hash(self, connection):
        email_hash = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e2'
        id_ = connection.get_id(email_hash=email_hash)
        assert id_ == 'ECHOECHO'
        
        
class TestReceptionCapabilities:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            invalid_connection.get_reception_capabilities('ECHOECHO')
        assert exc_info.value.response.status_code == 401

    def test_invalid_length(self, connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            connection.get_reception_capabilities('TEST')
        assert exc_info.value.response.status_code == 404

    def test_unknown_id(self, connection):
        with pytest.raises(ReceptionCapabilitiesServerError) as exc_info:
            connection.get_reception_capabilities('00000000')
        assert exc_info.value.response.status_code == 404

    def test_valid_id(self, connection):
        key = connection.get_reception_capabilities('ECHOECHO')
        assert key == {
            ReceptionCapability.text,
            ReceptionCapability.image,
            ReceptionCapability.video
        }


class TestCredits:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(CreditsServerError) as exc_info:
            invalid_connection.get_credits()
        assert exc_info.value.response.status_code == 401

    def test_valid(self, connection):
        assert connection.get_credits() == 100


class TestSendSimple:
    def test_invalid_identity(self, invalid_connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=invalid_connection,
                id='ECHOECHO',
                text='Hello'
            ).send()
        assert exc_info.value.response.status_code == 401

    def test_insufficient_credits(self, nocredit_connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=nocredit_connection,
                id='ECHOECHO',
                text='Hello'
            ).send()
        assert exc_info.value.response.status_code == 402

    def test_message_too_long(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=connection,
                id='ECHOECHO',
                text='0' * 3501
            ).send()
        assert exc_info.value.response.status_code == 413

    def test_unknown_id(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=connection,
                id='00000000',
                text='Hello'
            ).send()
        assert exc_info.value.response.status_code == 400

    def test_unknown_email(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=connection,
                email='somemail@example.com',
                text='Hello'
            ).send()
        assert exc_info.value.response.status_code == 404

    def test_unknown_phone(self, connection):
        with pytest.raises(MessageServerError) as exc_info:
            simple.TextMessage(
                connection=connection,
                phone='44987654321',
                text='Hello'
            ).send()
        assert exc_info.value.response.status_code == 404

    def test_via_id(self, connection):
        id_ = simple.TextMessage(
            connection=connection,
            id='ECHOECHO',
            text='0' * 3500
        ).send()
        assert id_ == '0' * 16

    def test_via_email(self, connection):
        id_ = simple.TextMessage(
            connection=connection,
            email='echoecho@example.com',
            text='Hello'
        ).send()
        assert id_ == '0' * 16

    def test_via_phone(self, connection):
        id_ = simple.TextMessage(
            connection=connection,
            phone='44123456789',
            text='Hello'
        ).send()
        assert id_ == '0' * 16
