try:
    # python3
    from unittest import mock
except ImportError:
    # python2
    import mock
import time

import pytest
import requests

from rbac.client.arborist.client import ArboristClient


@pytest.fixture(scope="session")
def arborist_base_url():
    """
    DON'T end with slash (because of usage in other fixtures). Anything else should be
    fine.
    """
    return ""


@pytest.fixture(scope="session")
def arborist_client(arborist_base_url):
    return ArboristClient(arborist_base_url=arborist_base_url)


@pytest.fixture(scope="session")
def mock_arborist_request(request, arborist_base_url):
    root = arborist_base_url

    def do_patch(response_mapping):
        defaults = {
            (root + "/health"): {
                "GET": (200, ""),
            }
        }
        defaults.update(response_mapping)
        response_mapping = defaults

        def mocker(method):

            def response_for(url, *args, **kwargs):
                mocked_response = mock.MagicMock(requests.Response)
                if url not in response_mapping:
                    mocked_response.status_code = 404
                    mocked_response.text = "NOT FOUND"
                    return mocked_response
                if method not in response_mapping[url]:
                    mocked_response.status_code = 405
                    mocked_response.text = "METHOD NOT ALLOWED"
                    return mocked_response
                code, content = response_mapping[url][method]
                mocked_response.status_code = code
                if isinstance(content, dict):
                    mocked_response.json.return_value = content
                else:
                    mocked_response.text = content
                return mocked_response

            return response_for

        for method in ["GET", "POST", "PATCH", "PUT", "DELETE"]:
            mocked_method = mock.MagicMock(side_effect=mocker(method))
            import_name = (
                "rbac.client.arborist.client.requests.{}"
                .format(method.lower())
            )
            patch_method = mock.patch(import_name, mocked_method)
            patch_method.start()
            request.addfinalizer(patch_method.stop)

    return do_patch


@pytest.fixture(autouse=True)
def no_backoff_delay(monkeypatch):
    """
    The ``backoff`` library uses ``time.sleep`` to implement the wait. Patch this to
    disable actually waiting at all in the tests.
    """
    monkeypatch.setattr(time, "sleep", lambda _: None)
