"""
You can modify and use one of the functions below to test the gateway
service with your end-to-end account.
"""
import asyncio

from threema.gateway import Connection, MessageError
from threema.gateway.e2e import TextMessage, ImageMessage, FileMessage

# Create a connection
connection = Connection(
    id='*YOUR_GATEWAY_THREEMA_ID',
    secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
    key='private:YOUR_PRIVATE_KEY'
)


@asyncio.coroutine
def send():
    """
    Send a message to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = TextMessage(
        connection=connection,
        id='ECHOECHO',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_cached_key():
    """
    Send a message to a specific Threema ID with an already cached
    public key of that recipient.
    """
    message = TextMessage(
        connection=connection,
        id='ECHOECHO',
        key='public:4a6a1b34dcef15d43cb74de2fd36091be99fbbaf126d099d47d83d919712c72b',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_cached_key_file():
    """
    Send a message to a specific Threema ID with an already cached
    public key (stored in a file) of that recipient.
    """
    message = TextMessage(
        connection=connection,
        id='ECHOECHO',
        key_file='ECHOECHO.txt',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_image():
    """
    Send an image to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = ImageMessage(
        connection=connection,
        id='ECHOECHO',
        image_path='res/threema.jpg'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_file():
    """
    Send a file to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = FileMessage(
        connection=connection,
        id='ECHOECHO',
        file_path='res/some_file.zip'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_file_with_thumbnail():
    """
    Send a file to a specific Threema ID including a thumbnail.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = FileMessage(
        connection=connection,
        id='ECHOECHO',
        file_path='res/some_file.zip',
        thumbnail_path='res/some_file_thumb.png'
    )
    return (yield from message.send())


@asyncio.coroutine
def main():
    try:
        yield from send()
        yield from send_cached_key()
        yield from send_cached_key_file()
        yield from send_image()
        yield from send_file()
        yield from send_file_with_thumbnail()
    except MessageError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
