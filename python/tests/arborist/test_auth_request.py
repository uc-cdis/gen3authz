import pytest

from gen3authz.utils import inline

pytestmark = pytest.mark.asyncio


@inline
def test_auth_request_positive(arborist_client, mock_arborist_request):
    mock_arborist_request({"/auth/request": {"POST": (200, {"auth": True})}})
    assert (
        yield arborist_client.auth_request("", "fence", "file_upload", "/data_upload")
    )
