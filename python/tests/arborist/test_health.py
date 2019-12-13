def test_health_endpoint(arborist_client, mock_arborist_request):
    mock_arborist_request({"/health": {"GET": (200, "OK")}})
    assert arborist_client.healthy()


def test_health_endpoint_unhealthy(arborist_client, mock_arborist_request):
    mock_arborist_request({"/health": {"GET": (400, "unhealthy")}})
    assert not arborist_client.healthy()
