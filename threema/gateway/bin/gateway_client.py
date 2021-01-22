"""
The command line interface for the Threema gateway service.
"""
import binascii
import os
import re

import aiohttp
import click
import logbook
import logbook.more

from threema.gateway import Connection
from threema.gateway import __version__ as _version
from threema.gateway import (
    e2e,
    feature_level,
    simple,
    util,
)
from threema.gateway.key import (
    HMAC,
    Key,
)
from threema.gateway.util import AioRunMixin

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

# Apply mock URL when starting CLI in debug mode
_test_port = os.environ.get('THREEMA_TEST_API')
if _test_port is not None:
    _mock_url = 'http://{}:{}'.format('127.0.0.1', _test_port)
    Connection.urls = {key: value.replace('https://msgapi.threema.ch', _mock_url)
                       for key, value in Connection.urls.items()}
    click.echo(('WARNING: Currently running in test mode!'
                'The Threema Gateway Server will not be contacted!'), err=True)


class _MockConnection(AioRunMixin):
    def __init__(self, private_key, public_key, identity=None):
        super().__init__(blocking=False)
        self.key = private_key
        self._public_key = public_key
        self.id = identity

    async def get_public_key(self, _):
        return self._public_key


@click.group()
@click.option('-v', '--verbosity', type=click.IntRange(0, len(_logging_levels)),
              default=0, help="Logging verbosity.")
@click.option('-c', '--colored', is_flag=True, help='Colourise logging output.')
@click.option('-vf', '--verify-fingerprint', is_flag=True,
              help='Verify the certificate fingerprint.')
@click.option('--fingerprint', type=str, help='A hex-encoded fingerprint.')
@click.pass_context
def cli(ctx, verbosity, colored, verify_fingerprint, fingerprint):
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

    # Fingerprint
    if fingerprint is not None:
        fingerprint = binascii.unhexlify(fingerprint)

    # Store on context
    ctx.obj = {
        'verify_fingerprint': verify_fingerprint,
        'fingerprint': fingerprint
    }


@cli.command(short_help='Show version information.', help="""
Show the current version of the Python SDK and the implemented feature
level.
""")
def version():
    click.echo('Version: {}'.format(_version))
    click.echo('Feature Level: {}'.format(feature_level))


@cli.command(short_help='Encrypt a text message.', help="""
Encrypt standard input using the given sender PRIVATE KEY and recipient
PUBLIC KEY. Prints two lines to standard output: first the nonce (hex),
and then the encrypted box (hex).
""")
@click.argument('private_key')
@click.argument('public_key')
@util.aio_run
async def encrypt(private_key, public_key):
    # Get key instances
    private_key = util.read_key_or_key_file(private_key, Key.Type.private)
    public_key = util.read_key_or_key_file(public_key, Key.Type.public)

    # Read text from stdin
    text = click.get_text_stream('stdin').read()

    # Print nonce and message as hex
    connection = _MockConnection(private_key, public_key)
    message = e2e.TextMessage(connection, text=text, to_id='')
    nonce, message = await message.send(get_data_only=True)
    click.echo()
    click.echo(binascii.hexlify(nonce))
    click.echo(binascii.hexlify(message))


@cli.command(short_help='Decrypt a text message.', help="""
Decrypt standard input using the given recipient PRIVATE KEY and sender PUBLIC KEY.
The NONCE must be given on the command line, and the box (hex) on standard input.
Prints the decrypted text message to standard output.
""")
@click.argument('private_key')
@click.argument('public_key')
@click.argument('nonce')
@util.aio_run
async def decrypt(private_key, public_key, nonce):
    # Get key instances
    private_key = util.read_key_or_key_file(private_key, Key.Type.private)
    public_key = util.read_key_or_key_file(public_key, Key.Type.public)

    # Convert nonce to bytes
    nonce = binascii.unhexlify(nonce)

    # Read message from stdin and convert to bytes
    message = click.get_text_stream('stdin').read()
    message = binascii.unhexlify(message)

    # Unpack message
    connection = _MockConnection(private_key, public_key)
    parameters = {'from_id': '', 'message_id': '', 'date': ''}
    message = await e2e.Message.receive(connection, parameters, nonce, message)

    # Ensure that this is a text message
    if message.type is not e2e.Message.Type.text_message:
        raise TypeError('Cannot decrypt message type {} in CLI'.format(message.type))

    # Print text
    click.echo()
    click.echo(message.text)


@cli.command(short_help='Generate a new key pair.', help="""
Generate a new key pair and write the PRIVATE and PUBLIC keys to
the respective files.
""")
@click.argument('private_key_file')
@click.argument('public_key_file')
def generate(private_key_file, public_key_file):
    # Generate key pair and hexlify both keys
    private_key, public_key = [Key.encode(key) for key in Key.generate_pair()]

    # Write keys to files
    with open(private_key_file, 'w') as sk_file, open(public_key_file, 'w') as pk_file:
        sk_file.write(private_key + '\n')
        pk_file.write(public_key + '\n')


# noinspection PyShadowingBuiltins
@cli.command(short_help='Hash an email address or phone number.', help="""
Hash an email address or a phone number for identity lookup.
Prints the hash in hex.
""")
@click.option('-e', '--email', help='An email address.')
@click.option('-p', '--phone', help='A phone number in E.164 format.')
def hash(**arguments):
    mode = {key: value for key, value in arguments.items() if value is not None}

    # Check that either email or phone has been specified
    if len(mode) != 1:
        error = 'Please specify exactly one email address or one phone number.'
        raise click.ClickException(error)

    # Unpack message and hash type
    hash_type, message = mode.popitem()

    # Email or phone?
    if hash_type == 'email':
        message = message.lower().strip()
    else:
        message = re.sub(r'[^0-9]', '', message)

    click.echo(HMAC.hash(message, hash_type).hexdigest())


@cli.command(short_help='Derive the public key from the private key.', help="""
Derive the public key that corresponds with the given PRIVATE KEY.
""")
@click.argument('private_key')
def derive(private_key):
    # Get private key instance and derive public key
    private_key = util.read_key_or_key_file(private_key, Key.Type.private)
    public_key = Key.derive_public(private_key)

    # Return hex encoded public key
    click.echo(Key.encode(public_key))


@cli.command(short_help='Send a text message using simple mode.', help="""
Send atext  message from standard input with server-side encryption to the given ID.
FROM is the API identity and SECRET is the API secret.
Prints the message ID on success.
""")
@click.argument('to')
@click.argument('from')
@click.argument('secret')
@click.pass_context
@util.aio_run
async def send_simple(ctx, **arguments):
    # Read message from stdin
    text = click.get_text_stream('stdin').read().strip()

    # Create connection
    connection = Connection(arguments['from'], arguments['secret'], **ctx.obj)
    async with connection:
        # Create message
        message = simple.TextMessage(
            connection=connection,
            to_id=arguments['to'],
            text=text
        )

        # Send message
        click.echo()
        click.echo(await message.send())


@cli.command(short_help='Send a text message using end-to-end mode.', help="""
Encrypt standard input and send the text message to the given ID.
FROM is the API identity and SECRET is the API secret.
Prints the message ID on success.
""")
@click.argument('to')
@click.argument('from')
@click.argument('secret')
@click.argument('private_key')
@click.option('-k', '--public-key', help="""
The public key of the recipient. Will be fetched automatically if not provided.
""")
@click.pass_context
@util.aio_run
async def send_e2e(ctx, **arguments):
    # Get key instances
    private_key = util.read_key_or_key_file(arguments['private_key'], Key.Type.private)
    if arguments['public_key'] is not None:
        public_key = util.read_key_or_key_file(arguments['public_key'], Key.Type.public)
    else:
        public_key = None

    # Read message from stdin
    text = click.get_text_stream('stdin').read().strip()

    # Create connection
    connection = Connection(
        identity=arguments['from'],
        secret=arguments['secret'],
        key=private_key,
        **ctx.obj
    )

    async with connection:
        # Create message
        message = e2e.TextMessage(
            connection=connection,
            to_id=arguments['to'],
            key=public_key,
            text=text
        )

        # Send message
        click.echo()
        click.echo(await message.send())


@cli.command(short_help='Send an image using end-to-end mode.', help="""
Encrypt and send an image ('jpeg' or 'png') to the given ID.
FROM is the API identity and SECRET is the API secret.
IMAGE_PATH is a relative or absolute path to an image.
Prints the message ID on success.
""")
@click.argument('to')
@click.argument('from')
@click.argument('secret')
@click.argument('private_key')
@click.argument('image_path')
@click.option('-k', '--public-key', help="""
The public key of the recipient. Will be fetched automatically if not provided.
""")
@click.pass_context
@util.aio_run
async def send_image(ctx, **arguments):
    # Get key instances
    private_key = util.read_key_or_key_file(arguments['private_key'], Key.Type.private)
    if arguments['public_key'] is not None:
        public_key = util.read_key_or_key_file(arguments['public_key'], Key.Type.public)
    else:
        public_key = None

    # Create connection
    connection = Connection(
        identity=arguments['from'],
        secret=arguments['secret'],
        key=private_key,
        **ctx.obj
    )

    async with connection:
        # Create message
        message = e2e.ImageMessage(
            connection=connection,
            to_id=arguments['to'],
            key=public_key,
            image_path=arguments['image_path']
        )

        # Send message
        click.echo(await message.send())


@cli.command(short_help='Send a video using end-to-end mode.', help="""
Encrypt and send a video ('mp4') including a thumbnail to the given ID.
FROM is the API identity and SECRET is the API secret.
VIDEO_PATH is a relative or absolute path to a video.
THUMBNAIL_PATH is a relative or absolute path to a thumbnail.
Prints the message ID on success.
""")
@click.argument('to')
@click.argument('from')
@click.argument('secret')
@click.argument('private_key')
@click.argument('video_path')
@click.argument('thumbnail_path')
@click.option('-k', '--public-key', help="""
The public key of the recipient. Will be fetched automatically if not provided.
""")
@click.option('-d', '--duration', help="""
Duration of the video in seconds. Defaults to 0.
""", default=0)
@click.pass_context
@util.aio_run
async def send_video(ctx, **arguments):
    # Get key instances
    private_key = util.read_key_or_key_file(arguments['private_key'], Key.Type.private)
    if arguments['public_key'] is not None:
        public_key = util.read_key_or_key_file(arguments['public_key'], Key.Type.public)
    else:
        public_key = None

    # Create connection
    connection = Connection(
        identity=arguments['from'],
        secret=arguments['secret'],
        key=private_key,
        **ctx.obj
    )

    async with connection:
        # Create message
        message = e2e.VideoMessage(
            connection=connection,
            to_id=arguments['to'],
            key=public_key,
            duration=arguments['duration'],
            video_path=arguments['video_path'],
            thumbnail_path=arguments['thumbnail_path']
        )

        # Send message
        click.echo(await message.send())


@cli.command(short_help='Send a file using end-to-end mode.', help="""
Encrypt and send a file to the given ID, optionally with a thumbnail.
FROM is the API identity and SECRET is the API secret.
FILE_PATH is a relative or absolute path to a file.
Prints the message ID on success.
""")
@click.argument('to')
@click.argument('from')
@click.argument('secret')
@click.argument('private_key')
@click.argument('file_path')
@click.option('-k', '--public-key', help="""
The public key of the recipient. Will be fetched automatically if not provided.
""")
@click.option('-t', '--thumbnail-path', help="""
The relative or absolute path to a thumbnail.
""")
@click.pass_context
@util.aio_run
async def send_file(ctx, **arguments):
    # Get key instances
    private_key = util.read_key_or_key_file(arguments['private_key'], Key.Type.private)
    if arguments['public_key'] is not None:
        public_key = util.read_key_or_key_file(arguments['public_key'], Key.Type.public)
    else:
        public_key = None

    # Create connection
    connection = Connection(
        identity=arguments['from'],
        secret=arguments['secret'],
        key=private_key,
        **ctx.obj
    )

    async with connection:
        # Create message
        message = e2e.FileMessage(
            connection=connection,
            to_id=arguments['to'],
            key=public_key,
            file_path=arguments['file_path'],
            thumbnail_path=arguments['thumbnail_path']
        )

        # Send message
        click.echo(await message.send())


@cli.command(short_help='Lookup a Threema ID or the public key.', help="""
Lookup the public key of the Threema ID or the ID linked to either the
given email address or the given phone number.
FROM is the API identity and SECRET is the API secret.
""")
@click.argument('from')
@click.argument('secret')
@click.option('-e', '--email', help='An email address.')
@click.option('-p', '--phone', help='A phone number in E.164 format.')
@click.option('-i', '--id', help='A Threema ID.')
@click.pass_context
@util.aio_run
async def lookup(ctx, **arguments):
    modes = ['email', 'phone', 'id']
    mode = {key: value for key, value in arguments.items()
            if key in modes and value is not None}

    # Check that one of the modes has been selected
    if len(mode) != 1:
        error = 'Please specify exactly one ID, one email address or one phone number.'
        raise click.ClickException(error)

    # Create connection
    connection = Connection(arguments['from'], secret=arguments['secret'], **ctx.obj)
    async with connection:
        # Do lookup
        if 'id' in mode:
            public_key = await connection.get_public_key(arguments['id'])
            click.echo(Key.encode(public_key))
        else:
            click.echo(await connection.get_id(**mode))


@cli.command(short_help='Lookup the reception capabilities of a Threema ID', help="""
Lookup the reception capabilities of a Threema ID.
FROM is the API identity and SECRET is the API secret.
Prints a set of capabilities in alphabetical order on success.
""")
@click.argument('from')
@click.argument('secret')
@click.argument('id')
@click.pass_context
@util.aio_run
async def capabilities(ctx, **arguments):
    # Create connection
    connection = Connection(arguments['from'], arguments['secret'], **ctx.obj)
    async with connection:
        # Lookup and format returned capabilities
        coroutine = connection.get_reception_capabilities(arguments['id'])
        capabilities_ = await coroutine
        click.echo(', '.join(sorted(capability.value for capability in capabilities_)))


# noinspection PyShadowingBuiltins
@cli.command(short_help='Get the number of credits left on the account', help="""
Retrieve the number of credits left on the used account.
FROM is the API identity and SECRET is the API secret.
""")
@click.argument('from')
@click.argument('secret')
@click.pass_context
@util.aio_run
async def credits(ctx, **arguments):
    # Create connection
    connection = Connection(arguments['from'], arguments['secret'], **ctx.obj)
    async with connection:
        # Get and print credits
        click.echo(await connection.get_credits())


def main():
    exc = None
    try:
        cli()
    except aiohttp.client_exceptions.ServerFingerprintMismatch:
        error = 'Fingerprints did not match!'
    except Exception as exc_:
        error = str(exc_)
        exc = exc_
    else:
        error = None

    # Print error (if any)
    if error is not None:
        click.echo('An error occurred:', err=True)
        click.echo(error, err=True)

        # Re-raise
        if exc is not None:
            raise exc

    # Remove logging handler
    if _logging_handler is not None:
        _logging_handler.pop_application()


if __name__ == '__main__':
    main()
