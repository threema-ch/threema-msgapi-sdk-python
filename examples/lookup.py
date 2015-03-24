"""
You can modify and use one of the lines below to test the lookup
functionality of the gateway service.
"""
from threema.gateway import Connection, IDError, Key


# Create a connection
connection = Connection('*YOUR_GATEWAY_THREEMA_ID', 'YOUR_GATEWAY_THREEMA_ID_SECRET')


def main():
    try:
        print(connection.get_id(phone='41791234567'))
        phone_hash = 'ad398f4d7ebe63c6550a486cc6e07f9baa09bd9d8b3d8cb9d9be106d35a7fdbc'
        print(connection.get_id(phone_hash=phone_hash))
        print(connection.get_id(email='test@threema.ch'))
        email_hash = '1ea093239cc5f0e1b6ec81b866265b921f26dc4033025410063309f4d1a8ee2c'
        print(connection.get_id(email_hash=email_hash))
        print(connection.get_public_key('ECHOECHO'))
        print(Key.encode(connection.get_public_key('ECHOECHO')))
    except IDError as exc:
        print('Error:', exc)


if __name__ == '__main__':
    main()
