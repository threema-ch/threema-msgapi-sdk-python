"""
You can modify and use one of the functions below to test the gateway
service with your account.
"""
import asyncio

import logbook
import logbook.more

from threema.gateway import (
    Connection,
    GatewayError,
    util,
)
from threema.gateway.simple import TextMessage


async def send_via_id(connection):
    """
    Send a message to a specific Threema ID.
    """
    message = TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        text='Hello from the world of Python!'
    )
    return await message.send()


async def send_via_email(connection):
    """
    Send a message via an email address.
    """
    message = TextMessage(
        connection=connection,
        email='test@threema.ch',
        text='Hello from the world of Python!'
    )
    return await message.send()


async def send_via_phone(connection):
    """
    Send a message via a phone number.
    """
    message = TextMessage(
        connection=connection,
        phone='41791234567',
        text='Hello from the world of Python!'
    )
    return await message.send()


async def main():
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        verify_fingerprint=True,
    )
    try:
        async with connection:
            await send_via_id(connection)
            await send_via_email(connection)
            await send_via_phone(connection)
    except GatewayError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.close()
