"""
You can modify and use one of the functions below to test the gateway
service with your account.
"""
import asyncio

import logbook
import logbook.more

from threema.gateway import util, Connection, GatewayError
from threema.gateway.simple import TextMessage


@asyncio.coroutine
def send_via_id(connection):
    """
    Send a message to a specific Threema ID.
    """
    message = TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        text='Hello from the world of Python!'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_via_email(connection):
    """
    Send a message via an email address.
    """
    message = TextMessage(
        connection=connection,
        email='test@threema.ch',
        text='Hello from the world of Python!'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_via_phone(connection):
    """
    Send a message via a phone number.
    """
    message = TextMessage(
        connection=connection,
        phone='41791234567',
        text='Hello from the world of Python!'
    )
    return (yield from message.send())


@asyncio.coroutine
def main():
    connection = Connection('*YOUR_GATEWAY_THREEMA_ID', 'YOUR_GATEWAY_THREEMA_ID_SECRET')
    try:
        with connection:
            yield from send_via_id(connection)
            yield from send_via_email(connection)
            yield from send_via_phone(connection)
    except GatewayError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.close()
