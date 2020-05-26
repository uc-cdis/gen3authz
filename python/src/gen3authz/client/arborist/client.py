"""
Define the ArboristClient class for interfacing with the arborist service for
authz.
"""

import httpx

try:
    import urllib.parse as urllib
except ImportError:
    import urllib

from .base import BaseArboristClient


class SyncClient(httpx.Client):
    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.__exit__(exc_type, exc_val, exc_tb)

    async def request(self, *args, **kwargs):
        return super().request(*args, **kwargs)


class ArboristClient(BaseArboristClient):
    """
    A singleton class for interfacing with the authz engine, "arborist".
    """

    client_cls = SyncClient
