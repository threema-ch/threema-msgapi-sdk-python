import asyncio

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


@asyncio.coroutine
def hello(request):
    return web.Response(body=b'Hello World')

router = UrlDispatcher()
router.add_route('GET', '/', hello)


class TestPrerequisities:
    @pytest.mark.asyncio
    def test_server(self, connection, mock_url):
        response = yield from connection._session.get(mock_url)
        assert response.status == 200
        assert (yield from response.read()) == b'Hello World'
