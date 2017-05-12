"""
You can modify and use one of the lines below to test the lookup
functionality of the gateway service.
"""
import logbook
import logbook.more

from threema.gateway import (
    Connection,
    GatewayError,
    util,
)
from threema.gateway.key import Key


def main():
    connection = Connection(
        identity='*YOUR_GATEWAY_THREEMA_ID',
        secret='YOUR_GATEWAY_THREEMA_ID_SECRET',
        verify_fingerprint=True,
        blocking=True,
    )
    try:
        with connection:
            print(connection.get_credits())
            print(connection.get_id(phone='41791234567'))
            hash_ = 'ad398f4d7ebe63c6550a486cc6e07f9baa09bd9d8b3d8cb9d9be106d35a7fdbc'
            print(connection.get_id(phone_hash=hash_))
            print(connection.get_id(email='test@threema.ch'))
            hash_ = '1ea093239cc5f0e1b6ec81b866265b921f26dc4033025410063309f4d1a8ee2c'
            print(connection.get_id(email_hash=hash_))
            key = connection.get_public_key('ECHOECHO')
            print(Key.encode(key))
            print(connection.get_reception_capabilities('ECHOECHO'))
    except GatewayError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    util.enable_logging(logbook.WARNING)
    log_handler = logbook.more.ColorizedStderrHandler()
    with log_handler.applicationbound():
        main()
