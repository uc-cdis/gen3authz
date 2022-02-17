import pytest

pytestmark = pytest.mark.asyncio


async def test_health_endpoint(arborist_client, mock_arborist_request, use_async):
    mock_arborist_request({"/health": {"GET": (200, "OK")}})
    if use_async:
        assert await arborist_client.healthy()
    else:
        assert arborist_client.healthy()


async def test_health_endpoint_unhealthy(
    arborist_client, mock_arborist_request, use_async
):
    mock_arborist_request({"/health": {"GET": (400, "unhealthy")}})
    if use_async:
        assert not await arborist_client.healthy()
    else:
        assert not arborist_client.healthy()
