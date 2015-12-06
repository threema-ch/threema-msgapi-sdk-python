import socket
import asyncio
import threading
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
    }}
    api_identity = (values['msgapi']['id'], values['msgapi']['secret'])
    values['msgapi']['api_identity'] = api_identity
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
    ready = threading.Event()

    def _loop_thread(event_loop, port):
        # Set up server
        asyncio.set_event_loop(event_loop)
        coroutine = event_loop.create_server(handler, host=pytest.msgapi.ip, port=port)
        task = event_loop.create_task(coroutine)
        event_loop.run_until_complete(task)
        server_ = task.result()
        ready.set()

        # Loop until stopped
        event_loop.run_forever()

        # Tear down server
        event_loop.run_until_complete(handler.finish_connections(1.0))
        server_.close()
        event_loop.run_until_complete(server_.wait_closed())
        event_loop.run_until_complete(app.finish())
        event_loop.close()

    def fin():
        def _stop():
            event_loop.stop()
        event_loop.call_soon_threadsafe(_stop)
        thread.join()

    request.addfinalizer(fin)

    # Start event loop in the background
    thread = threading.Thread(target=_loop_thread, args=(event_loop, port))
    thread.start()
    ready.wait()


@pytest.fixture(scope='module')
def mock_url(port):
    """
    Return the URL where the test server can be reached.
    """
    return 'http://{}:{}'.format(pytest.msgapi.ip, port)


@pytest.fixture(scope='module')
def connection(server, mock_url):
    # Note: We're not doing anything with the server but obviously the
    # server needs to be started to be able to connect
    connection_ = threema.gateway.Connection(pytest.msgapi.id, pytest.msgapi.secret)

    # Patch URLs
    connection_.urls = {key: value.replace(pytest.msgapi.base_url, mock_url)
                        for key, value in connection_.urls.items()}
    return connection_


@pytest.fixture(scope='module')
def invalid_connection(connection):
    invalid_connection_ = copy.deepcopy(connection)
    invalid_connection_.id = '*NOEXIST'
    invalid_connection_.secret = 'nomock'
    return invalid_connection_
