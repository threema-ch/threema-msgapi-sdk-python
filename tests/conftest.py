import socket
import asyncio
import copy

import pytest

import threema.gateway

from contextlib import closing

from aiohttp import web


def pytest_namespace():
    values = {'msgapi': {
        'base_url': 'https://msgapi.threema.ch',
        'ip': '127.0.0.1',
        'id': '*MOCKING',
        'secret': 'mock',
        'key': 'private:dd9413d597092b004fedc4895db978425efa328ba1f1ec6729e46e09231b8a7e',
        'nocredit_id': 'NOCREDIT',
        'noexist_id': '*NOEXIST',
    }}
    values['msgapi']['api_identities'] = {
        (values['msgapi']['id'], values['msgapi']['secret']),
        (values['msgapi']['nocredit_id'], values['msgapi']['secret'])
    }
    return values


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
def event_loop(request):
    """
    Create an instance of the default event loop.
    """
    policy = asyncio.get_event_loop_policy()
    policy.get_event_loop().close()
    _event_loop = policy.new_event_loop()
    policy.set_event_loop(_event_loop)
    request.addfinalizer(_event_loop.close)
    return _event_loop


@pytest.fixture(scope='module')
def port():
    return unused_tcp_port()


@pytest.fixture(scope='module')
def server(request, event_loop, port):
    router = getattr(request.module, 'router')
    app = web.Application(loop=event_loop, router=router)
    handler = app.make_handler()

    # Set up server
    coroutine = event_loop.create_server(handler, host=pytest.msgapi.ip, port=port)
    task = event_loop.create_task(coroutine)
    event_loop.run_until_complete(task)
    server_ = task.result()

    def fin():
        event_loop.run_until_complete(handler.finish_connections(1.0))
        server_.close()
        event_loop.run_until_complete(server_.wait_closed())
        event_loop.run_until_complete(app.finish())

    request.addfinalizer(fin)


@pytest.fixture(scope='module')
def mock_url(port):
    """
    Return the URL where the test server can be reached.
    """
    return 'http://{}:{}'.format(pytest.msgapi.ip, port)


@pytest.fixture(scope='module')
def connection(request, server, mock_url):
    # Note: We're not doing anything with the server but obviously the
    # server needs to be started to be able to connect
    connection_ = threema.gateway.Connection(
        identity=pytest.msgapi.id,
        secret=pytest.msgapi.secret,
        key=pytest.msgapi.key
    )

    # Patch URLs
    connection_.urls = {key: value.replace(pytest.msgapi.base_url, mock_url)
                        for key, value in connection_.urls.items()}

    def fin():
        connection_.close()

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
    task = event_loop.create_task(coroutine)
    event_loop.run_until_complete(task)
    return task.result()
