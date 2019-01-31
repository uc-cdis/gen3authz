def test_auth_request_positive(arborist_client, mock_arborist_request):
    mock_arborist_request({
        "/auth/request": {"POST": (200, {"auth": True})}
    })
    assert arborist_client.auth_request({})
