import pytest

pytestmark = pytest.mark.asyncio


async def test_health_endpoint(arborist_client, mock_arborist_request):
    mock_arborist_request({"/health": {"GET": (200, "OK")}})
    assert await arborist_client.healthy()


async def test_health_endpoint_unhealthy(arborist_client, mock_arborist_request):
    mock_arborist_request({"/health": {"GET": (400, "unhealthy")}})
    assert not await arborist_client.healthy()
