"""
You can modify and use one of the functions below to test the gateway
service with your end-to-end account.
"""
import asyncio

import logbook
import logbook.more

from threema.gateway import (
    Connection,
    GatewayError,
    util,
)
from threema.gateway.e2e import (
    FileMessage,
    ImageMessage,
    TextMessage,
    VideoMessage,
)


async def send(connection):
    """
    Send a message to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return await message.send()


async def send_cached_key(connection):
    """
    Send a message to a specific Threema ID with an already cached
    public key of that recipient.
    """
    message = TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        key='public:4a6a1b34dcef15d43cb74de2fd36091be99fbbaf126d099d47d83d919712c72b',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return await message.send()


async def send_cached_key_file(connection):
    """
    Send a message to a specific Threema ID with an already cached
    public key (stored in a file) of that recipient.
    """
    message = TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        key_file='ECHOECHO.txt',
        text='私はガラスを食べられます。それは私を傷つけません。'
    )
    return await message.send()


async def send_image(connection):
    """
    Send an image to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = ImageMessage(
        connection=connection,
        to_id='ECHOECHO',
        image_path='res/threema.jpg'
    )
    return await message.send()


async def send_video(connection):
    """
    Send a video including a thumbnail to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = VideoMessage(
        connection=connection,
        to_id='ECHOECHO',
        duration=1,
        video_path='res/threema.mp4',
        thumbnail_path='res/threema.jpg',
    )
    return await message.send()


async def send_file(connection):
    """
    Send a file to a specific Threema ID.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = FileMessage(
        connection=connection,
        to_id='ECHOECHO',
        file_path='res/some_file.zip'
    )
    return await message.send()


async def send_file_with_thumbnail(connection):
    """
    Send a file to a specific Threema ID including a thumbnail.

    Note that the public key will be automatically fetched from the
    Threema servers. It is strongly recommended that you cache
    public keys to avoid querying the API for each message.
    """
    message = FileMessage(
        connection=connection,
        to_id='ECHOECHO',
        file_path='res/some_file.zip',
        thumbnail_path='res/some_file_thumb.png'
    )
    return await message.send()


async def main():
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        key='private:YOUR_PRIVATE_KEY',
        verify_fingerprint=True,
    )
    try:
        async with connection:
            await send(connection)
            await send_cached_key(connection)
            await send_cached_key_file(connection)
            await send_image(connection)
            await send_video(connection)
            await send_file(connection)
            await send_file_with_thumbnail(connection)
    except GatewayError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.close()
