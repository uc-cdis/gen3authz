import httpx

from .base import BaseArboristClient


class Client(httpx.AsyncClient):
    def __enter__(self):
        return self.__aenter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.__aexit__(exc_type, exc_val, exc_tb)


class ArboristClient(BaseArboristClient):
    client_cls = Client

    # This is used for backoff.on_predicate to detect async correctly
    async def healthy(self, timeout=1):
        return await super().healthy(timeout)
