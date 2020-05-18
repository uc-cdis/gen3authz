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


class ArboristClient(BaseArboristClient):
    """
    A singleton class for interfacing with the authz engine, "arborist".
    """

    client_cls = httpx.Client
