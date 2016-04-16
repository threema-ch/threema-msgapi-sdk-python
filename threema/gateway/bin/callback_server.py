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


def aio_run(func, run_forever=False):
    func = asyncio.coroutine(func)

    def _wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        task = loop.create_task(func(*args, **kwargs))
        loop.run_until_complete(task)
        if run_forever:
            loop.run_forever()
        return task.result()
    return functools.update_wrapper(_wrapper, func)


def aio_serve(func):
    return aio_run(func, run_forever=True)


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
@aio_serve
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
    yield from callback.create_server(host=host, port=port)


def main():
    # with server.logging_handler.applicationbound():
    try:
        cli()
    except Exception as exc:
        click.echo('An error occurred:', err=True)
        click.echo(exc, err=True)
