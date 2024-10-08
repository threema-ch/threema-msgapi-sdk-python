import functools
import ssl

import logbook
import logbook.more
from aiohttp import web

from threema.gateway import (
    Connection,
    e2e,
    util,
)


async def handle_message(message):
    print('Got message ({}): {}'.format(repr(message), message))


async def on_startup(connection, application):
    message = e2e.TextMessage(
        connection=connection,
        to_id='ECHOECHO',
        text='Hi!'
    )
    await message.send()


async def create_application():
    # Create connection instance
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        key='private:YOUR_PRIVATE_KEY'
    )

    # Create the web server application
    application = e2e.create_application(connection)

    # Register the handler for incoming messages
    e2e.add_callback_route(
        connection, application, handle_message, path='/gateway_callback')

    # Register startup hook (to send an outgoing message in this example)
    application.on_startup.append(functools.partial(on_startup, connection))

    return application


def main():
    # Create an SSL context to terminate TLS.
    # Note: It is usually advisable to use a reverse proxy instead in front of
    #       the server that terminates TLS, e.g. Nginx.
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='YOUR_CERTFILE', keyfile='YOUR_KEYFILE')

    # Run a server that listens on any interface via port 8443. It will
    # gracefully shut down when Ctrl+C has been pressed.
    web.run_app(create_application(), port=8443, ssl_context=ssl_context)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        main()
