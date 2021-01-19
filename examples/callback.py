import ssl

import logbook
import logbook.more
from aiohttp import web

from threema.gateway import (
    Connection,
    util,
)
from threema.gateway.e2e import (
    add_callback_route,
    create_application,
)


async def handle_message(message):
    print('Got message ({}): {}'.format(repr(message), message))


def serve():
    # Create connection instance
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        key='private:YOUR_PRIVATE_KEY'
    )

    # Create the application and register the handler for incoming messages
    application = create_application(connection)
    add_callback_route(connection, application, handle_message, path='/gateway_callback')

    # Create an SSL context to terminate TLS.
    # Note: It is usually advisable to use a reverse proxy instead in front of
    #       the server that terminates TLS, e.g. Nginx.
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='YOUR_CERTFILE', keyfile='YOUR_KEYFILE')

    # Run a server that listens on any interface via port 8443. It will
    # gracefully shut down when Ctrl+C has been pressed.
    web.run_app(application, port=8443, ssl_context=ssl_context)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        serve()
