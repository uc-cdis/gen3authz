import pytest


pytestmark = pytest.mark.asyncio


async def test_auth_request_positive(arborist_client, mock_arborist_request):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert await arborist_client.auth_request(
        "", "fence", "file_upload", "/data_upload"
    )


@pytest.mark.parametrize("use_async", [False], indirect=["use_async"])
def test_sync_auth_request_positive(arborist_client, mock_arborist_request, use_async):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert (
        arborist_client.auth_request("", "fence", "file_upload", "/data_upload") is True
    )
