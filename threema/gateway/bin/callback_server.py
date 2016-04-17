"""
The command line interface for the Threema Gateway Callback Server.
"""
import functools
import asyncio

import click

from threema.gateway import __version__ as _version
from threema.gateway import util, Connection
from threema.gateway.key import Key
from threema.gateway.e2e import AbstractCallback


class Callback(AbstractCallback):
    @asyncio.coroutine
    def receive_message(self, message):
        click.echo('Got message ({}): {}'.format(repr(message), message))


def aio_serve(close_func):
    loop = asyncio.get_event_loop()

    def decorator(func):
        func = asyncio.coroutine(func)

        def wrapper(*args, **kwargs):
            # Start
            click.echo('Starting')
            task = loop.create_task(func(*args, **kwargs))
            loop.run_until_complete(task)
            open_result = task.result()
            click.echo('Started')
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            click.echo('Closing')
            task = loop.create_task(close_func(open_result))
            loop.run_until_complete(task)
            close_result = task.result()
            click.echo('Closed')
            return open_result, close_result

        return functools.update_wrapper(wrapper, func)

    return decorator


@click.group()
@click.pass_context
def cli(ctx):
    """
    Command Line Interface. Use --help for details.
    """
    ctx.obj = {}


@cli.command(short_help='Show version information.', help="""
Show the current version of the Threema Gateway Callback Server.
""")
def version():
    click.echo('Version: {}'.format(_version))


@asyncio.coroutine
def close_server(server_and_callback):
    server, callback = server_and_callback
    yield from callback.handler.finish_connections(1.0)
    server.close()
    yield from server.wait_closed()
    yield from callback.application.finish()


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
    callback = Callback(connection, certfile=certfile, keyfile=keyfile)

    # Create server
    return (yield from callback.create_server(host=host, port=port)), callback


def main():
    # with server.logging_handler.applicationbound():
    try:
        cli()
    except Exception as exc:
        click.echo('An error occurred:', err=True)
        click.echo(exc, err=True)
        raise
