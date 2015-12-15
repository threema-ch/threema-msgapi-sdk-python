"""
You can modify and use one of the functions below to test the gateway
service with your account.
"""
import asyncio

from threema.gateway import Connection, MessageError
from threema.gateway.simple import TextMessage


# Create a connection
connection = Connection('*YOUR_GATEWAY_THREEMA_ID', 'YOUR_GATEWAY_THREEMA_ID_SECRET')


@asyncio.coroutine
def send_via_id():
    """
    Send a message to a specific Threema ID.
    """
    message = TextMessage(
        connection=connection,
        id='ECHOECHO',
        text='Hello from the world of Python!'
    )
    return (yield from message.send())


@asyncio.coroutine
def send_via_email():
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
def send_via_phone():
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
    try:
        yield from send_via_id()
        yield from send_via_email()
        yield from send_via_phone()
    except MessageError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
