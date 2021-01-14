import pytest

from threema.gateway import e2e


class TestCallback:
    @pytest.mark.asyncio
    async def test_invalid_message(self, connection, callback_send, raw_message):
        outgoing = raw_message(
            connection=connection,
            to_id=pytest.msgapi.id,
            nonce=b'0' * 24,
            message=b'1' * 200
        )
        response = await callback_send(outgoing)
        assert response.status == 400
        await response.release()

    @pytest.mark.asyncio
    async def test_delivery_receipt(self, connection, callback_send, callback_receive):
        outgoing = e2e.DeliveryReceipt(
            connection=connection,
            to_id=pytest.msgapi.id,
            receipt_type=e2e.DeliveryReceipt.ReceiptType.read,
            message_ids=[b'0' * 8, b'1' * 8],
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.receipt_type == incoming.receipt_type
        assert outgoing.message_ids == incoming.message_ids

    @pytest.mark.asyncio
    async def test_text_message(self, connection, callback_send, callback_receive):
        outgoing = e2e.TextMessage(
            connection,
            to_id=pytest.msgapi.id,
            text='私はガラスを食べられます。それは私を傷つけません。!',
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.text == incoming.text

    @pytest.mark.asyncio
    async def test_image_message(
        self, connection, callback_send, callback_receive, server
    ):
        outgoing = e2e.ImageMessage(
            connection,
            to_id=pytest.msgapi.id,
            image_path=server.threema_jpg,
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.image == incoming.image

    @pytest.mark.asyncio
    async def test_video(self, connection, callback_send, callback_receive, server):
        outgoing = e2e.VideoMessage(
            connection,
            to_id=pytest.msgapi.id,
            duration=1,
            video_path=server.threema_mp4,
            thumbnail_path=server.threema_jpg,
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.duration == incoming.duration
        assert outgoing.video == incoming.video
        assert outgoing.thumbnail_content == incoming.thumbnail_content

    @pytest.mark.asyncio
    async def test_file_message(
        self, connection, callback_send, callback_receive, server
    ):
        outgoing = e2e.FileMessage(
            connection,
            to_id=pytest.msgapi.id,
            file_path=server.threema_jpg,
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.file_content == incoming.file_content

    @pytest.mark.asyncio
    async def test_file_message_thumb(
            self, connection, callback_send, callback_receive, server
    ):
        outgoing = e2e.FileMessage(
            connection,
            to_id=pytest.msgapi.id,
            file_path=server.threema_jpg,
            thumbnail_path=server.threema_jpg,
        )
        response = await callback_send(outgoing)
        await response.release()
        incoming = await callback_receive()
        assert outgoing.from_id == incoming.from_id
        assert outgoing.to_id == incoming.to_id
        assert outgoing.file_content == incoming.file_content
        assert outgoing.thumbnail_content == incoming.thumbnail_content
