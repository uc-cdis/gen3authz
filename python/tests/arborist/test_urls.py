"""
Run some basic tests that the methods on ``ArboristClient`` actually try to hit
the correct URLs on the arborist API.
"""

try:
    # python3
    from unittest import mock
except ImportError:
    # python2
    import mock


def test_get_resource_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/resource/a/b/c": {"GET": (200, {"is": 789})}})
    assert arborist_client.get_resource("/a/b/c") == {"is": 789}
    mock_get.assert_called_with(
        "get",
        arborist_client._base_url + "/resource/a/b/c",
        allow_redirects=True,
        params=None,
    )


def test_list_policies_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/policy/": {"GET": (200, {"is": 789})}})
    assert arborist_client.list_policies() == {"is": 789}
    mock_get.assert_called_with(
        "get", arborist_client._base_url + "/policy/", allow_redirects=True, params=None
    )


def test_policies_not_exist_call(arborist_client, mock_arborist_request):
    mock_get = mock_arborist_request({"/policy/": {"GET": (200, {"is": 789})}})
    assert arborist_client.policies_not_exist(["foo-bar"]) == ["foo-bar"]
    mock_get.assert_called_with(
        "get", arborist_client._base_url + "/policy/", allow_redirects=True, params=None
    )


def test_create_resource_call(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/resource/": {"POST": (200, {"is": 789})}})
    assert arborist_client.create_resource("/", {"name": "test"}) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/resource/",
        data=None,
        json={"name": "test"},
    )


def test_create_role_call(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/role/": {"POST": (200, {"is": 789})}})
    assert arborist_client.create_role({"id": "test"}) == {"is": 789}
    mock_post.assert_called_with(
        "post", arborist_client._base_url + "/role/", data=None, json={"id": "test"}
    )


def test_create_policy(arborist_client, mock_arborist_request):
    mock_post = mock_arborist_request({"/policy/": {"POST": (200, {"is": 789})}})
    assert arborist_client.create_policy(
        {"id": "test", "resource_paths": ["/"], "role_ids": ["test"]}
    ) == {"is": 789}
    mock_post.assert_called_with(
        "post",
        arborist_client._base_url + "/policy/",
        data=None,
        json={"id": "test", "resource_paths": ["/"], "role_ids": ["test"]},
    )
