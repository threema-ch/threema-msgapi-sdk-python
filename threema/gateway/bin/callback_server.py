"""
The command line interface for the Threema Gateway Callback Server.
"""
import asyncio
import functools

import click
import logbook
import logbook.more

from threema.gateway import Connection
from threema.gateway import __version__ as _version
from threema.gateway import util
from threema.gateway.e2e import AbstractCallback
from threema.gateway.key import Key

_logging_handler = None
_logging_levels = {
    1: logbook.CRITICAL,
    2: logbook.ERROR,
    3: logbook.WARNING,
    4: logbook.NOTICE,
    5: logbook.INFO,
    6: logbook.DEBUG,
    7: logbook.TRACE,
}


class Callback(AbstractCallback):
    async def receive_message(self, message):
        click.echo('Got message ({}): {}'.format(repr(message), message))


def aio_serve(close_func):
    loop = asyncio.get_event_loop()

    def decorator(func):
        func = asyncio.coroutine(func)

        def wrapper(*args, **kwargs):
            # Start
            click.echo('Starting')
            open_result = loop.run_until_complete(func(*args, **kwargs))
            click.echo('Started')
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            click.echo('Closing')
            close_result = loop.run_until_complete(close_func(open_result))
            loop.close()
            click.echo('Closed')
            return open_result, close_result

        return functools.update_wrapper(wrapper, func)

    return decorator


@click.group()
@click.option('-v', '--verbosity', type=click.IntRange(0, len(_logging_levels)),
              default=0, help="Logging verbosity.")
@click.option('-c', '--colored', is_flag=True, help='Colourise logging output.')
@click.pass_context
def cli(ctx, verbosity, colored):
    """
    Command Line Interface. Use --help for details.
    """
    if verbosity > 0:
        # Enable logging
        util.enable_logging(level=_logging_levels[verbosity])

        # Get handler class
        if colored:
            handler_class = logbook.more.ColorizedStderrHandler
        else:
            handler_class = logbook.StderrHandler

        # Set up logging handler
        handler = handler_class(level=_logging_levels[verbosity])
        handler.push_application()
        global _logging_handler
        _logging_handler = handler

    # Create context object
    ctx.obj = {}


@cli.command(short_help='Show version information.', help="""
Show the current version of the Threema Gateway Callback Server.
""")
def version():
    click.echo('Version: {}'.format(_version))


async def close_server(server_and_callback):
    server, callback = server_and_callback
    server.close()
    await server.wait_closed()
    await callback.close()


@cli.command(short_help='Start the callback server.', help="""
Start the Threema Gateway Callback Server.
FROM is the API identity and SECRET is the API secret.
CERT represents the path to a file in PEM format containing the SSL
certificate of the server.""")
@click.argument('identity')
@click.argument('secret')
@click.argument('private_key')
@click.argument('cert', type=click.Path(exists=True))
@click.option('-k', '--keyfile', type=click.Path(exists=True), help="""
Path to a file that contains the private key. Will be read from
CERTFILE if not present.""")
@click.option('-h', '--host', help='Bind to a specific host.')
@click.option('-p', '--port', default=443, help='Listen on a specific port.')
@aio_serve(close_server)
def serve(**arguments):
    # Get arguments
    identity = arguments['identity']
    secret = arguments['secret']
    private_key = util.read_key_or_key_file(arguments['private_key'], Key.Type.private)
    certfile = arguments['cert']
    keyfile = arguments.get('keyfile')
    host = arguments.get('host')
    port = arguments['port']

    # Create connection and callback instances
    connection = Connection(identity=identity, secret=secret, key=private_key)
    callback = Callback(connection)

    # Create server
    coroutine = callback.create_server(certfile, keyfile=keyfile, host=host, port=port)
    server = await coroutine
    return server, callback


def main():
    try:
        cli()
    except Exception as exc:
        click.echo('An error occurred:', err=True)
        click.echo(exc, err=True)
        raise
    finally:
        if _logging_handler is not None:
            _logging_handler.pop_application()


if __name__ == '__main__':
    main()
