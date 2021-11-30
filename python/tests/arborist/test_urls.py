"""
Run some basic tests that the methods on ``ArboristClient`` actually try to hit
the correct URLs on the arborist API.
"""
import pytest
import datetime
from gen3authz.client.arborist.errors import ArboristError

pytestmark = pytest.mark.asyncio


async def test_get_resource_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/resource/a/b/c": {"GET": (200, {"is": 789})}})
    assert await arborist_client.get_resource("/a/b/c") == {"is": 789}
    mock_get.assert_called_with(
        "get",
        arborist_client._base_url + "/resource/a/b/c",
        follow_redirects=True,
        params=None,
        timeout=10,
    )


async def test_list_policies_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/policy/": {"GET": (200, {"is": 789})}})
    assert await arborist_client.list_policies() == {"is": 789}
    mock_get.assert_called_with(
        "get",
        arborist_client._base_url + "/policy/",
        follow_redirects=True,
        params=None,
        timeout=10,
    )


async def test_policies_not_exist_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/policy/": {"GET": (200, {"is": 789})}})
    assert await arborist_client.policies_not_exist(["foo-bar"]) == ["foo-bar"]
    mock_get.assert_called_with(
        "get",
        arborist_client._base_url + "/policy/",
        follow_redirects=True,
        params=None,
        timeout=10,
    )


async def test_create_resource_call(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/resource/": {"POST": (200, {"is": 789})}})
    assert await arborist_client.create_resource("/", {"name": "test"}) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/resource/",
        data=None,
        json={"name": "test"},
        timeout=10,
    )


async def test_create_role_call(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/role/": {"POST": (200, {"is": 789})}})
    assert await arborist_client.create_role({"id": "test"}) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/role/",
        data=None,
        json={"id": "test"},
        timeout=10,
    )


async def test_create_policy(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/policy/": {"POST": (200, {"is": 789})}})
    assert await arborist_client.create_policy(
        {"id": "test", "resource_paths": ["/"], "role_ids": ["test"]}
    ) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/policy/",
        data=None,
        json={"id": "test", "resource_paths": ["/"], "role_ids": ["test"]},
        timeout=10,
    )


async def test_create_policy_with_ctx(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/policy/": {"POST": (200, {"is": 789})}})
    with arborist_client.context(authz_provider="ttt"):
        assert await arborist_client.create_policy(
            {"id": "test", "resource_paths": ["/"], "role_ids": ["test"]}
        ) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/policy/",
        data=None,
        json={"id": "test", "resource_paths": ["/"], "role_ids": ["test"]},
        headers={"X-AuthZ-Provider": "ttt"},
        timeout=10,
    )


async def test_grant_user_policy(arborist_client, mock_arborist_request):
    username = "johnsmith"
    expires_at = int(
        datetime.datetime(
            year=2021,
            month=11,
            day=23,
            hour=9,
            minute=30,
            second=1,
            tzinfo=datetime.timezone.utc,
        ).timestamp()
    )
    mock_post = mock_arborist_request(
        {f"/user/{username}/policy": {"POST": (204, None)}}
    )
    assert (
        await arborist_client.grant_user_policy(
            username, "test_policy", expires_at=expires_at
        )
        == 204
    )
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + f"/user/{username}/policy",
        data=None,
        json={"policy": "test_policy", "expires_at": "2021-11-23T09:30:01Z"},
        timeout=10,
    )


async def test_update_user(arborist_client, mock_arborist_request):
    username = "johnsmith"
    new_username = "janesmith"
    new_email = "janesmith@domain.tld"
    mock_post = mock_arborist_request({f"/user/{username}": {"PATCH": (204, None)}})
    response = await arborist_client.update_user(
        username, new_username=new_username, new_email=new_email
    )
    assert response.code == 204
    mock_post.assert_called_with(
        "patch",
        arborist_client._base_url + f"/user/{username}",
        data=None,
        json={"name": new_username, "email": new_email},
        timeout=10,
    )


async def test_update_user_raises_error(arborist_client, mock_arborist_request):
    username = "johnsmith"
    new_username = "janesmith"
    mock_post = mock_arborist_request({f"/user/{username}": {"PATCH": (500, None)}})
    with pytest.raises(ArboristError):
        response = await arborist_client.update_user(
            username, new_username=new_username
        )
