import httpx

from .base import BaseArboristClient


class ArboristClient(BaseArboristClient):
    client_cls = httpx.AsyncClient

    # This is used for backoff.on_predicate to detect async correctly
    async def healthy(self, timeout=1):
        return await super().healthy(timeout)
