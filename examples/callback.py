import asyncio
import ipaddress

import logbook
import logbook.more

from threema.gateway import (
    Connection,
    util,
)
from threema.gateway.e2e import AbstractCallback


class Callback(AbstractCallback):
    async def receive_message(self, message):
        print('Got message ({}): {}'.format(repr(message), message))


async def start():
    # Create connection instance
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        key='private:YOUR_PRIVATE_KEY'
    )

    # Create the callback instance
    route = '/gateway_callback'
    callback = Callback(connection, route=route)

    # Start the callback server and listen on any interface at port 8443
    server = await callback.create_server(
        certfile='PATH_TO_SSL_PEM_CERTIFICATE_CHAIN',
        keyfile='PATH_TO_SSL_PRIVATE_KEY',
        port=8443
    )

    # Return both server and callback instance
    return server, callback


async def stop(server, callback):
    server.close()
    await server.wait_closed()
    await callback.close()


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        loop = asyncio.get_event_loop()
        # Start server
        server, callback = loop.run_until_complete(start())
        # Ctrl+C: Terminate the server and the callback application
        try:
            print('Listening on:\n')
            for socket in server.sockets:
                host, port, *_ = socket.getsockname()
                host = ipaddress.ip_address(host)
                if isinstance(host, ipaddress.IPv6Address):
                    host = '[{}]'.format(host)
                print('  https://{}:{}{}'.format(host, port, callback.route))
            print('\nStarted callback server. Press Ctrl+C to terminate.')
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        loop.run_until_complete(stop(server, callback))
        loop.close()
