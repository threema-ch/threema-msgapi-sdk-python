from threema.gateway import (
    e2e,
    simple,
)


def test_lookup_id_by_phone(connection_blocking):
    identity = connection_blocking.get_id(phone='44123456789')
    assert identity == 'ECHOECHO'


def test_lookup_id_by_phone_hash(connection_blocking):
    hash_ = '98b05f6eda7a878f6f016bdcdc9db6eb61a6b190e814ff787142115af144214c'
    identity = connection_blocking.get_id(phone_hash=hash_)
    assert identity == 'ECHOECHO'


def test_lookup_public_key(connection_blocking, server):
    key = connection_blocking.get_public_key('ECHOECHO')
    assert key.hex_pk() == server.echoecho_key


def test_lookup_reception_capabilities(connection_blocking):
    capabilities = connection_blocking.get_reception_capabilities('ECHOECHO')
    assert len(capabilities) == 4


def test_send_e2e_text_message(connection_blocking):
    message = e2e.TextMessage(
        connection=connection_blocking,
        to_id='ECHOECHO',
        text='Hello. This works quite nicely!',
    )
    id_ = message.send()
    assert id_ == '1' * 16


def test_send_simple_text_message(connection_blocking):
    message = simple.TextMessage(
        connection=connection_blocking,
        to_id='ECHOECHO',
        text='Hello. This works quite nicely!',
    )
    id_ = message.send()
    assert id_ == '0' * 16
