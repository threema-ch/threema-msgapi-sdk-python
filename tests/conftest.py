import asyncio
import asyncio.subprocess
import binascii
import collections
import copy
import hashlib
import hmac
import os
import socket
import ssl
import subprocess
import sys
import time
from contextlib import closing

import aiohttp
import pytest
from aiohttp import web

import threema.gateway
from threema.gateway import e2e
from threema.gateway.key import Key

_res_path = os.path.normpath(os.path.join(
    os.path.abspath(__file__), os.pardir, 'res'))


class RawMessage(e2e.Message):
    def __init__(self, connection, nonce=None, message=None, **kwargs):
        super().__init__(connection, e2e.Message.Type.text_message, **kwargs)
        self.nonce = nonce
        self.message = message

    async def pack(self, writer):
        raise NotImplementedError

    @classmethod
    async def unpack(cls, connection, parameters, key_pair, reader):
        raise NotImplementedError

    async def send(self, get_data_only=False):
        """
        Send the raw message

        Return the ID of the message.
        """
        # Send message
        if get_data_only:
            return self.nonce, self.message
        else:
            return await self._connection.send_e2e(**{
                'to': self.to_id,
                'nonce': binascii.hexlify(self.nonce).decode(),
                'box': binascii.hexlify(self.message).decode()
            })


class Server:
    def __init__(self):
        self.threema_jpg = os.path.join(_res_path, 'threema.jpg')
        self.threema_mp4 = os.path.join(_res_path, 'threema.mp4')
        key = b'4a6a1b34dcef15d43cb74de2fd36091be99fbbaf126d099d47d83d919712c72b'
        self.echoecho_key = key
        self.echoecho_encoded_key = 'public:' + key.decode('ascii')
        decoded_private_key = Key.decode(pytest.msgapi.private, Key.Type.private)
        self.mocking_key = Key.derive_public(decoded_private_key).hex_pk()
        self.blobs = {}
        self.latest_blob_ids = []
        self.routes = [
            web.get('/pubkeys/{key}', self.pubkeys),
            web.get('/lookup/phone/{phone}', self.lookup_phone),
            web.get('/lookup/phone_hash/{phone_hash}', self.lookup_phone_hash),
            web.get('/lookup/email/{email}', self.lookup_email),
            web.get('/lookup/email_hash/{email_hash}', self.lookup_email_hash),
            web.get('/capabilities/{id}', self.capabilities),
            web.get('/credits', self.credits),
            web.post('/send_simple', self.send_simple),
            web.post('/send_e2e', self.send_e2e),
            web.post('/upload_blob', self.upload_blob),
            web.get('/blobs/{blob_id}', self.download_blob),
        ]

    async def pubkeys(self, request):
        key = request.match_info['key']
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif len(key) != 8:
            return web.Response(status=404)
        elif key == 'ECHOECHO':
            return web.Response(body=self.echoecho_key)
        elif key == '*MOCKING':
            return web.Response(body=self.mocking_key)
        return web.Response(status=404)

    async def lookup_phone(self, request):
        phone = request.match_info['phone']
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif not phone.isdigit():
            return web.Response(status=404)
        elif phone == '44123456789':
            return web.Response(body=b'ECHOECHO')
        return web.Response(status=404)

    async def lookup_phone_hash(self, request):
        phone_hash = request.match_info['phone_hash']
        from_, secret = request.query['from'], request.query['secret']
        hash_ = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214c'
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif len(phone_hash) % 2 != 0:
            # Note: This status code might not be intended and may change in the future
            return web.Response(status=500)
        elif len(phone_hash) != 64:
            return web.Response(status=400)
        elif phone_hash == hash_:
            return web.Response(body=b'ECHOECHO')
        return web.Response(status=404)

    async def lookup_email(self, request):
        email = request.match_info['email']
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif email == 'echoecho@example.com':
            return web.Response(body=b'ECHOECHO')
        return web.Response(status=404)

    async def lookup_email_hash(self, request):
        email_hash = request.match_info['email_hash']
        from_, secret = request.query['from'], request.query['secret']
        hash_ = '45a13d422b40f81936a9987245d3f6d9064c90607273af4f578246b4484669e2'
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif len(email_hash) % 2 != 0:
            # Note: This status code might not be intended and may change in the future
            return web.Response(status=500)
        elif len(email_hash) != 64:
            return web.Response(status=400)
        elif email_hash == hash_:
            return web.Response(body=b'ECHOECHO')
        return web.Response(status=404)

    async def capabilities(self, request):
        id_ = request.match_info['id']
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        elif id_ == 'ECHOECHO':
            return web.Response(body=b'text,image,video,file')
        elif id_ == '*MOCKING':
            return web.Response(body=b'text,image,video,file')
        return web.Response(status=404)

    async def credits(self, request):
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)
        return web.Response(body=b'100')

    async def send_simple(self, request):
        post = await request.post()

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

    async def send_e2e(self, request):
        post = await request.post()

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

    async def upload_blob(self, request):
        try:
            data = await request.post()

            # Check API identity
            api_identity = (request.query['from'], request.query['secret'])
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
        blob_id = hashlib.sha256(blob).hexdigest()[:32]

        # Process
        if request.query['from'] == pytest.msgapi.nocredit_id:
            return web.Response(status=402)
        elif len(blob) == 0:
            return web.Response(status=400)
        elif len(blob) > 20 * (2**20):
            return web.Response(status=413)

        # Store blob and return
        self.blobs[blob_id] = blob
        self.latest_blob_ids.append(blob_id)
        return web.Response(body=blob_id.encode())

    async def download_blob(self, request):
        blob_id = request.match_info['blob_id']

        # Check API identity
        from_, secret = request.query['from'], request.query['secret']
        if (from_, secret) not in pytest.msgapi.api_identities:
            return web.Response(status=401)

        # Get blob
        try:
            blob = self.blobs[blob_id]
        except KeyError:
            return web.Response(status=404)
        else:
            return web.Response(
                body=blob,
                content_type='application/octet-stream'
            )


def pytest_addoption(parser):
    help_ = 'loop: Use a different event loop, supported: asyncio, uvloop'
    parser.addoption("--loop", action="store", help=help_)


def pytest_report_header(config):
    return 'Using event loop: {}'.format(default_event_loop(config=config))


def pytest_namespace():
    private = 'private:dd9413d597092b004fedc4895db978425efa328ba1f1ec6729e46e09231b8a7e'
    public = Key.encode(Key.derive_public(Key.decode(private, Key.Type.private)))
    values = {'msgapi': {
        'cli_path': os.path.join(
            os.path.dirname(__file__),
            '../threema/gateway/bin/gateway_client.py',
        ),
        'cert_path': os.path.join(_res_path, 'cert.pem'),
        'base_url': 'https://msgapi.threema.ch',
        'ip': '127.0.0.1',
        'id': '*MOCKING',
        'secret': 'mock',
        'private': private,
        'public': public,
        'nocredit_id': 'NOCREDIT',
        'noexist_id': '*NOEXIST',
    }}
    values['msgapi']['api_identities'] = {
        (values['msgapi']['id'], values['msgapi']['secret']),
        (values['msgapi']['nocredit_id'], values['msgapi']['secret'])
    }
    return values


def default_event_loop(request=None, config=None):
    if request is not None:
        config = request.config
    loop = config.getoption("--loop")
    if loop == 'uvloop':
        import uvloop  # noqa
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    else:
        loop = 'asyncio'
    return loop


def unused_tcp_port():
    """
    Find an unused localhost TCP port from 1024-65535 and return it.
    """
    with closing(socket.socket()) as sock:
        sock.bind((pytest.msgapi.ip, 0))
        return sock.getsockname()[1]


def identity():
    return pytest.msgapi.id, pytest.msgapi.secret


@pytest.fixture(scope='module')
def server():
    return Server()


@pytest.fixture(scope='module')
def raw_message():
    return RawMessage


@pytest.fixture(scope='module')
def event_loop(request):
    """
    Create an instance of the requested event loop.
    """
    default_event_loop(request=request)

    # Close previous event loop
    policy = asyncio.get_event_loop_policy()
    policy.get_event_loop().close()

    # Create new event loop
    _event_loop = policy.new_event_loop()
    policy.set_event_loop(_event_loop)

    def fin():
        _event_loop.close()

    # Add finaliser and return new event loop
    request.addfinalizer(fin)
    return _event_loop


@pytest.fixture(scope='module')
def api_server_port():
    return unused_tcp_port()


@pytest.fixture(scope='module')
def api_server(request, event_loop, api_server_port, server):
    async def start_server():
        port = api_server_port
        app = web.Application(client_max_size=100 * (2**20))
        app.router.add_routes(server.routes)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host=pytest.msgapi.ip, port=port, shutdown_timeout=1.0)
        await site.start()
        return app, runner, site
    app, runner, site = event_loop.run_until_complete(start_server())

    def fin():
        async def stop_server():
            await site.stop()
            await runner.cleanup()
            await app.cleanup()
        event_loop.run_until_complete(stop_server())

    request.addfinalizer(fin)


@pytest.fixture(scope='module')
def mock_url(api_server_port):
    """
    Return the URL where the test server can be reached.
    """
    return 'http://{}:{}'.format(pytest.msgapi.ip, api_server_port)


@pytest.fixture(scope='module')
def connection(request, event_loop, api_server, mock_url):
    async def create_connection():
        # Note: We're not doing anything with the server but obviously the
        # server needs to be started to be able to connect
        return threema.gateway.Connection(
            identity=pytest.msgapi.id,
            secret=pytest.msgapi.secret,
            key=pytest.msgapi.private,
        )
    connection_ = event_loop.run_until_complete(create_connection())

    # Patch URLs
    connection_.urls = {key: value.replace(pytest.msgapi.base_url, mock_url)
                        for key, value in connection_.urls.items()}

    def fin():
        event_loop.run_until_complete(connection_.close())

    request.addfinalizer(fin)
    return connection_


@pytest.fixture(scope='module')
def connection_blocking(request, event_loop, api_server, mock_url):
    async def create_connection():
        # Note: We're not doing anything with the server but obviously the
        # server needs to be started to be able to connect
        return threema.gateway.Connection(
            identity=pytest.msgapi.id,
            secret=pytest.msgapi.secret,
            key=pytest.msgapi.private,
            blocking=True,
        )
    connection_ = event_loop.run_until_complete(create_connection())

    # Patch URLs
    connection_.urls = {key: value.replace(pytest.msgapi.base_url, mock_url)
                        for key, value in connection_.urls.items()}

    def fin():
        event_loop.run_until_complete(connection_.close())

    request.addfinalizer(fin)
    return connection_


@pytest.fixture(scope='module')
def invalid_connection(connection):
    invalid_connection_ = copy.copy(connection)
    invalid_connection_.id = pytest.msgapi.noexist_id
    return invalid_connection_


@pytest.fixture(scope='module')
def nocredit_connection(connection):
    nocredit_connection_ = copy.copy(connection)
    nocredit_connection_.id = pytest.msgapi.nocredit_id
    return nocredit_connection_


@pytest.fixture(scope='module')
def blob():
    return b'\x01\x02\x03'


@pytest.fixture(scope='module')
def blob_id(event_loop, connection, blob):
    coroutine = connection.upload(blob)
    return event_loop.run_until_complete(coroutine)


@pytest.fixture(scope='module')
def cli(api_server, api_server_port, event_loop):
    async def call_cli(*args, input=None, timeout=3.0):
        # Prepare environment
        env = os.environ.copy()
        env['THREEMA_TEST_API'] = str(api_server_port)
        test_api_mode = 'WARNING: Currently running in test mode!'

        # Call CLI in subprocess and get output
        parameters = [sys.executable, pytest.msgapi.cli_path] + list(args)
        if isinstance(input, str):
            input = input.encode('utf-8')

        # Create process
        create = asyncio.create_subprocess_exec(
            *parameters, env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        process = await create

        # Wait for process to terminate
        coroutine = process.communicate(input=input)
        output, _ = await asyncio.wait_for(coroutine, timeout)

        # Process output
        output = output.decode('utf-8')
        if test_api_mode not in output:
            print(output)
            raise ValueError('Not running in test mode')

        # Strip leading empty lines and pydev debugger output
        rubbish = [
            'pydev debugger: process',
            'Traceback (most recent call last):',
            test_api_mode,
        ]
        lines = []
        skip_following_empty_lines = True
        for line in output.splitlines(keepends=True):
            if any((line.startswith(s) for s in rubbish)):
                skip_following_empty_lines = True
            elif not skip_following_empty_lines or len(line.strip()) > 0:
                lines.append(line)
                skip_following_empty_lines = False

        # Strip trailing empty lines
        empty_lines_count = 0
        for line in reversed(lines):
            if len(line.strip()) > 0:
                break
            empty_lines_count += 1
        if empty_lines_count > 0:
            lines = lines[:-empty_lines_count]
        output = ''.join(lines)

        # Check return code
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, parameters,
                                                output=output)
        return output
    return call_cli


@pytest.fixture(scope='module')
def private_key_file(tmpdir_factory):
    file = tmpdir_factory.mktemp('keys').join('private_key')
    file.write(pytest.msgapi.private)
    return str(file)


@pytest.fixture(scope='module')
def public_key_file(tmpdir_factory):
    file = tmpdir_factory.mktemp('keys').join('public_key')
    file.write(pytest.msgapi.public)
    return str(file)


Callback = collections.namedtuple('Callback', ['queue', 'handle_message'])


@pytest.fixture(scope='module')
def callback(event_loop, connection):
    async def create_callback():
        queue = asyncio.Queue()

        async def handle_message(message):
            await queue.put(message)

        return Callback(queue, handle_message)
    return event_loop.run_until_complete(create_callback())


@pytest.fixture(scope='module')
def callback_server_port():
    return unused_tcp_port()


@pytest.fixture(scope='module')
def callback_server(request, event_loop, connection, callback, callback_server_port):
    async def start_callback_server():
        app = e2e.create_application(connection)
        e2e.add_callback_route(connection, app, callback.handle_message)
        runner = web.AppRunner(app)
        await runner.setup()

        cert_path = pytest.msgapi.cert_path
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cert_path)
        site = web.TCPSite(
            runner, host=pytest.msgapi.ip, port=callback_server_port,
            ssl_context=ssl_context)
        await site.start()

        return app, runner, site
    app, runner, site = event_loop.run_until_complete(start_callback_server())

    def fin():
        async def stop_callback_server():
            await site.stop()
            await runner.cleanup()
            await app.cleanup()
        event_loop.run_until_complete(stop_callback_server())

    request.addfinalizer(fin)


@pytest.fixture(scope='module')
def callback_client(request, event_loop, callback_server):
    async def create_client():
        # Note: This is ONLY required because we are using a self-signed certificate
        #       for test purposes.
        connector_ = aiohttp.TCPConnector(ssl=False)
        session_ = aiohttp.ClientSession(connector=connector_)
        return connector_, session_
    connector, session = event_loop.run_until_complete(create_client())

    def fin():
        event_loop.run_until_complete(session.close())

    request.addfinalizer(fin)
    return session


@pytest.fixture(scope='module')
def callback_send(callback_client, callback_server_port, connection):
    async def send(message):
        # Get data from message
        nonce, data = await message.send(get_data_only=True)

        # Create callback parameters
        params = {
            'from': connection.id,
            'to': message.to_id,
            'messageId': hashlib.sha256(message.to_id.encode('ascii')).hexdigest()[16:],
            'date': str(time.time()),
            'nonce': binascii.hexlify(nonce).decode('ascii'),
            'box': binascii.hexlify(data).decode('ascii'),
        }

        # Calculate MAC
        message = ''.join((params['from'], params['to'], params['messageId'],
                           params['date'], params['nonce'], params['box']))
        message = message.encode('ascii')
        encoded_secret = connection.secret.encode('ascii')
        hmac_ = hmac.new(encoded_secret, msg=message, digestmod=hashlib.sha256)
        params['mac'] = hmac_.hexdigest()

        # Send message
        url = 'https://{}:{}/gateway_callback'.format(
            pytest.msgapi.ip, callback_server_port)
        return await callback_client.post(url, data=params)

    return send


@pytest.fixture(scope='module')
def callback_receive(event_loop, callback, callback_server):
    async def receive(timeout=3.0):
        coroutine = asyncio.wait_for(callback.queue.get(), timeout)
        return await coroutine

    return receive
