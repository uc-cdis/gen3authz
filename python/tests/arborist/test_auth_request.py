import pytest


pytestmark = pytest.mark.asyncio


async def test_auth_request_resources_positive(arborist_client, mock_arborist_request):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert await arborist_client.auth_request(
        "", "fence", "file_upload", "/data_upload"
    )


@pytest.mark.parametrize("use_async", [False], indirect=["use_async"])
def test_sync_auth_request_resources_positive(
    arborist_client, mock_arborist_request, use_async
):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert (
        arborist_client.auth_request("", "fence", "file_upload", "/data_upload") is True
    )


async def test_auth_request_authz_positive(arborist_client, mock_arborist_request):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert await arborist_client.auth_request(
        jwt="",
        service="fence",
        methods="file_upload",
        authz={
            "version": "1.0",
            "logic": {"resource": "/programs/foo/projects/bar"},
        },
    )


async def test_auth_request_resources_or_authz(arborist_client):
    with pytest.raises(AssertionError, match="Expected either"):
        await arborist_client.auth_request(
            jwt="",
            service="fence",
            methods="file_upload",
        )

    with pytest.raises(AssertionError, match="Expected either"):
        await arborist_client.auth_request(
            jwt="",
            service="fence",
            methods="file_upload",
            resources="data_upload",
            authz={
                "version": "1.0",
                "logic": {"resource": "/programs/foo/projects/bar"},
            },
        )
