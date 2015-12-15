import asyncio

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


@asyncio.coroutine
def hello(request):
    return web.Response(body=b'Hello World')

router = UrlDispatcher()
router.add_route('GET', '/', hello)


class TestPrerequisities:
    def test_server(self, connection, mock_url):
        response = connection._session.get(mock_url)
        assert response.status == 200
        assert response.content == b'Hello World'
