"""
Base classes for interfacing with the arborist service for authz. Please use
:class:`~.client.ArboristClient` in blocking context like Flask, or
:class:`~.async_client.ArboristClient` in asynchronous context like FastAPI.
"""

import inspect
import json
from collections import deque
from urllib.parse import quote

import backoff
import contextvars
import httpx
from cdislogging import get_logger

from ..arborist.errors import ArboristError, ArboristUnhealthyError
from ..base import AuthzClient
from ... import string_types
from ...utils import maybe_sync


def _escape_newlines(text):
    return text.replace("\n", "\\n")


class ArboristResponse(object):
    """
    Args:
        response (requests.Response)
    """

    def __init__(self, response, expect_json=True):
        self._response = response
        self.code = response.status_code

        if not expect_json:
            return

        try:
            self.json = response.json()
        except ValueError as e:
            if self.code != 500:
                raise ArboristError(
                    "got a confusing response from arborist, couldn't parse JSON from"
                    " response but got code {} for this response: {}".format(
                        self.code, _escape_newlines(response.text)
                    ),
                    self.code,
                )
            self.json = {"error": {"message": str(e), "code": 500}}

    @property
    def successful(self):
        try:
            return "error" not in self.json
        except AttributeError:
            return self.code < 400

    @property
    def error_msg(self):
        if self.successful:
            return None
        try:
            return self.json["error"]["message"]
        except (KeyError, AttributeError):
            return self._response.text


class EnvContext(object):
    __slots__ = ("_stack", "_kwargs")

    def __init__(self, stack, kwargs):
        self._stack = stack
        self._kwargs = kwargs

    def __enter__(self):
        kwargs = {}
        if self._stack:
            kwargs.update(self._stack[-1])
        kwargs.update(self._kwargs)
        self._stack.append(kwargs)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stack.pop()


class _Env(object):
    __slots__ = ("_local",)

    def __init__(self):
        self._local = contextvars.ContextVar("stack")

    def _get_stack(self):
        stack = self._local.get(None)
        if stack is None:
            stack = deque()
            self._local.set(stack)
        return stack

    def get_current_with(self, kwargs):
        rv = {}
        stack = self._get_stack()
        if stack:
            rv.update(stack[-1])
        rv.update(kwargs)
        return rv

    def make_context(self, kwargs):
        return EnvContext(self._get_stack(), kwargs)


class BaseArboristClient(AuthzClient):
    """
    Abstract class to define behavior of an authz client implementation.
    """

    client_cls = NotImplemented

    def __init__(
        self,
        logger=None,
        arborist_base_url="http://arborist-service/",
        authz_provider=None,
        timeout=10,
    ):
        self.logger = logger or get_logger("ArboristClient")
        self._base_url = arborist_base_url.strip("/")
        self._auth_url = self._base_url + "/auth/"
        self._health_url = self._base_url + "/health"
        self._policy_url = self._base_url + "/policy/"
        self._resource_url = self._base_url + "/resource"
        self._role_url = self._base_url + "/role/"
        self._user_url = self._base_url + "/user"
        self._client_url = self._base_url + "/client"
        self._group_url = self._base_url + "/group"
        self._authz_provider = authz_provider
        self._timeout = timeout
        self._env = _Env()

    def context(self, **kwargs):
        return self._env.make_context(kwargs)

    async def request(self, method, url, **kwargs):
        """
        Wrapper method of ``requests.request`` adding retry, timeout and headers.

        If the actual request fails to connect or timed out, this client will retry the
        same request if ``retry`` is truthy after Arborist becomes healthy.
        By default, it will retry health check up to 5 times, waiting for a maximum of
        10 seconds, before giving up and declaring Arborist unavailable.

        Args:
            method:
            url:
            kwargs:
                expect_json:
                    True (default) if the response should be in JSON format
                retry:
                    True (default) if the request should be retried, or a dict as
                    keyword arguments for ``backoff.on_predicate``
                timeout:
                    overwrite timeout parameter for ``requests``
        """
        expect_json = kwargs.pop("expect_json", True)
        kwargs = self._env.get_current_with(kwargs)
        retry = kwargs.pop("retry", True)
        authz_provider = kwargs.pop("authz_provider", self._authz_provider)

        kwargs.setdefault("timeout", self._timeout)
        if authz_provider:
            headers = kwargs.setdefault("headers", {})
            headers["X-AuthZ-Provider"] = authz_provider
        async with self.client_cls() as client:
            try:
                rv = await client.request(method, url, **kwargs)
            except httpx.TimeoutException:
                if retry:
                    if isinstance(retry, bool):
                        retry = {}
                    # set some defaults for when to give up: after 5 failures, or 10
                    # seconds (these can be overridden by keyword arguments)
                    retry.setdefault("max_tries", 5)
                    retry.setdefault("max_time", 10)

                    def giveup():
                        raise ArboristUnhealthyError()

                    def wait_gen():
                        # shorten the wait times between retries a little to fit our
                        # scale a little better (aim to give up within 10 s)
                        for n in backoff.fibo():
                            yield n / 2.0

                    await backoff.on_predicate(wait_gen, on_giveup=giveup, **retry)(
                        self.healthy
                    )()
                    rv = await client.request(method, url, **kwargs)
                else:
                    raise
        return ArboristResponse(rv, expect_json=expect_json)

    def get(self, url, params=None, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("get", url, params=params, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request("post", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.request("put", url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.request("patch", url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("delete", url, **kwargs)

    @maybe_sync
    async def get_users(self, params=None, **kwargs):
        return await self.get(url=self._user_url, params=params, **kwargs)

    @maybe_sync
    async def healthy(self, timeout=1):
        """
        Indicate whether the arborist service is available and functioning.

        Return:
            bool: whether arborist service is available
        """
        try:
            response = await self.get(
                self._health_url, retry=False, timeout=timeout, expect_json=False
            )
        except httpx.HTTPError as e:
            self.logger.error(
                "arborist unavailable; got requests exception: {}".format(str(e))
            )
            return False
        if response.code != 200:
            self.logger.error(
                "arborist not healthy; {} returned code {}".format(
                    self._health_url, response.code
                )
            )
        return response.code == 200

    @maybe_sync
    async def auth_mapping(self, username):
        """
        For given user, get mapping from the resources that this user can access
        to the actions on those resources for which they are authorized.

        Return:
            dict: response JSON from arborist
        """
        data = {"username": username}
        response = await self.post(self._auth_url.rstrip("/") + "/mapping", json=data)
        if not response.successful:
            raise ArboristError(response.error_msg, response.code)
        return response.json

    @maybe_sync
    async def auth_request(self, jwt, service, methods, resources):
        """
        Return:
            bool: authorization response
        """
        if isinstance(resources, string_types):
            resources = [resources]
        if isinstance(methods, string_types):
            methods = [methods]
        data = {
            "user": {"token": jwt},
            "requests": [
                {"resource": resource, "action": {"service": service, "method": method}}
                for resource in resources
                for method in methods
            ],
        }
        response = await self.post(self._auth_url.rstrip("/") + "/request", json=data)
        if not response.successful:
            msg = "request to arborist failed: {}".format(response.error_msg)
            raise ArboristError(msg, response.code)
        elif response.code == 200:
            return bool(response.json["auth"])
        else:
            # arborist could send back a 400 for things like, the user has some policy
            # that it doesn't recognize, or the request is structured incorrectly; for
            # these cases we will default to unauthorized
            msg = "arborist could not process auth request: {}".format(
                response.error_msg
            )
            self.logger.info(msg)
            raise ArboristError(msg, response.code)

    @maybe_sync
    async def create_resource(self, parent_path, resource_json, create_parents=False):

        """
        Create a new resource in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Used for syncing projects from dbgap into arborist resources.

        Example schema for resource JSON:

            {
                "name": "some_resource",
                "description": "..."
                "subresources": [
                    {
                        "name": "subresource",
                        "description": "..."
                    }
                ]
            }

        Supposing we have some ``"parent_path"``, then the new resource will be
        created as ``/parent_path/some_resource`` in arborist.

        ("description" fields are optional, as are subresources, which default
        to empty.)

        Args:
            parent_path (str):
                the path (like a filepath) to the parent resource above this
                one; if this one is in the root level, then use "/"
            resource_json (dict):
                dictionary of resource information (see the example above)
            create_parents (bool):
                if True, then arborist will create parent resources if they do
                not exist yet.

        Return:
            dict: response JSON from arborist

        Raises:
            - ArboristError: if the operation failed (couldn't create resource)
        """
        # To add a subresource, all we actually have to do is POST the resource
        # JSON to its parent in arborist:
        #
        #     POST /resource/parent
        #
        # and now the new resource will exist here:
        #
        #     /resource/parent/new_resource
        #

        path = self._resource_url + quote(parent_path)
        if create_parents:
            path = path + "?p"

        response = await self.post(path, json=resource_json)
        if response.code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warning(
                "resource `{}` already exists in arborist".format(resource_json["name"])
            )
            return None
        if not response.successful:
            msg = "could not create resource `{}` in arborist: {}".format(
                path, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created resource {}".format(resource_json["name"]))
        return response.json

    @maybe_sync
    async def list_resources(self):
        """
        Return the information for all resources in Arborist.

        Return:
            dict: JSON representation of the resource
        """
        response = await self.get(self._resource_url)
        if response.code != 200:
            self.logger.error("could not list resources: {}".format(response.error_msg))
            raise ArboristError(response.error_msg, response.code)
        resources = response.json
        self.logger.info(
            "got arborist resources: `{}`".format(json.dumps(resources, indent=2))
        )
        return resources

    @maybe_sync
    async def get_resource(self, path):
        """
        Return the information for a resource in Arborist.

        Args:
            path (str): path for the resource

        Return:
            dict: JSON representation of the resource
        """
        url = self._resource_url + quote(path)
        response = await self.get(url)
        if response.code == 404:
            return None
        if not response.successful:
            self.logger.error(response.error_msg)
            raise ArboristError(response.error_msg, response.code)
        return response.json

    @maybe_sync
    async def update_resource(self, path, resource_json, create_parents=False):
        url = self._resource_url + quote(path)
        if create_parents:
            url = url + "?p"
        response = await self.put(url, json=resource_json)
        if not response.successful:
            msg = "could not update resource `{}` in arborist: {}".format(
                path, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("updated resource {}".format(resource_json["name"]))
        return response.json

    @maybe_sync
    async def delete_resource(self, path):
        url = self._resource_url + quote(path)
        response = await self.delete(url)
        if response.code not in [204, 404]:
            msg = "could not delete resource `{}` in arborist: {}".format(
                path, response.error_msg
            )
            raise ArboristError(msg, response.code)
        return True

    @maybe_sync
    async def policies_not_exist(self, policy_ids):
        """
        Return any policy IDs which do not exist in arborist. (So, if the
        result is empty, all provided IDs were valid.)

        Return:
            list: policies (if any) that don't exist in arborist
        """
        res = self.list_policies()
        if inspect.isawaitable(res):  # handle list_policies maybe_sync
            res = await res
        existing_policies = res.get("policies", [])
        return [
            policy_id for policy_id in policy_ids if policy_id not in existing_policies
        ]

    @maybe_sync
    async def create_role(self, role_json):
        """
        Create a new role in arborist (does not affect fence database or
        otherwise have any interaction with userdatamodel).

        Used for syncing project permissions from dbgap into arborist roles.

        Example schema for the role JSON:

            {
                "id": "role",
                "description": "...",
                "permissions": [
                    {
                        "id": "permission",
                        "description": "...",
                        "action": {
                            "service": "...",
                            "method": "..."
                        },
                        "constraints": {
                            "key": "value",
                        }
                    }
                ]
            }

        ("description" fields are optional, as is the "constraints" field in
        the permission.)

        Args:
            role_json (dict): dictionary of information about the role

        Return:
            dict: response JSON from arborist

        Raises:
            - ArboristError: if the operation failed (couldn't create role)
        """
        response = await self.post(self._role_url, json=role_json)
        if response.code == 409:
            # already exists; this is ok
            return None
        if not response.successful:
            msg = "could not create role `{}` in arborist: {}".format(
                role_json["id"], response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created role {}".format(role_json["id"]))
        return response.json

    @maybe_sync
    async def list_roles(self):
        return await self.get(self._role_url)

    @maybe_sync
    async def update_role(self, role_id, role_json):
        url = self._role_url + quote(role_id)
        response = await self.put(url, json=role_json)
        if not response.successful:
            msg = "could not update role `{}` in arborist: {}".format(
                role_id, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("updated role {}".format(role_id))
        return response

    @maybe_sync
    async def delete_role(self, role_id):
        response = await self.delete(self._role_url + quote(role_id))
        if response.code == 404:
            # already doesn't exist, this is fine
            return
        elif response.code >= 400:
            msg = "could not delete role in arborist: {}".format(response.error_msg)
            self.logger.error(msg)
            raise ArboristError(msg, response.code)

    @maybe_sync
    async def get_policy(self, policy_id):
        """
        Return the JSON representation of a policy with this ID.
        """
        response = await self.get(self._policy_url + quote(policy_id))
        if response.code == 404:
            return None
        return response.json

    @maybe_sync
    async def delete_policy(self, path):
        return (await self.delete(self._policy_url + quote(path))).json

    @maybe_sync
    async def create_policy(self, policy_json, skip_if_exists=True):
        return await self._create_policy(policy_json, skip_if_exists)

    async def _create_policy(self, policy_json, skip_if_exists=True):
        response = await self.post(self._policy_url, json=policy_json)
        if response.code == 409 and skip_if_exists:
            # already exists; this is ok, but leave warning
            self.logger.warning(
                "policy `{}` already exists in arborist".format(policy_json["id"])
            )
            return None
        if not response.successful:
            msg = "could not create policy `{}` in arborist: {}".format(
                policy_json["id"], response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created policy {}".format(policy_json["id"]))
        return response.json

    @maybe_sync
    async def list_policies(self):
        """
        List the existing policies.

        Return:
            dict: response JSON from arborist

        Example:

            {
                "policy_ids": [
                    "policy-abc",
                    "policy-xyz"
                ]
            }

        """
        return (await self.get(self._policy_url)).json

    @maybe_sync
    async def update_policy(self, policy_id, policy_json, create_if_not_exist=False):
        """
        Arborist will create policy if not exist and overwrite if exist.
        """
        if "id" in policy_json and policy_json.pop("id") != policy_id:
            self.logger.warning(
                "id in policy_json provided but not equal to policy_id, ignoring."
            )
        try:
            # Arborist 3.x.x
            url = self._policy_url + quote(policy_id)
            response = await self.put(url, json=policy_json)
        except ArboristError as e:
            if e.code == 405:
                # For compatibility with Arborist 2.x.x
                self.logger.info(
                    "This Arborist version has no PUT /policy/{policyID} endpt yet."
                    "Falling back on PUT /policy"
                )
                policy_json["id"] = policy_id
                response = await self.put(self._policy_url, json=policy_json)
            else:
                raise
        if response.code == 404 and create_if_not_exist:
            self.logger.info("Policy `{}` does not exist: Creating".format(policy_id))
            policy_json["id"] = policy_id
            return await self._create_policy(policy_json, skip_if_exists=False)
        if not response.successful:
            msg = "could not put policy `{}` in arborist: {}".format(
                policy_id, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("put policy {}".format(policy_id))
        return response

    @maybe_sync
    async def create_user(self, user_info):
        """
        Args:
            user_info (dict):
                user information that goes in the request to arborist; see arborist docs
                for required field names. notably it's `name` not `username`
        """
        if "name" not in user_info:
            raise ValueError("create_user requires username `name` in user info")
        response = await self.post(self._user_url, json=user_info)
        if response.code == 409:
            # already exists
            return
        elif response.code != 201:
            self.logger.error(response.error_msg)

    @maybe_sync
    async def list_resources_for_user(self, username):
        """
        Args:
            username (str)

        Return:
            List[str]: list of resource paths which the user has any access to
        """
        url = "{}/{}/resources".format(self._user_url, quote(username))
        response = await self.get(url)
        if response.code != 200:
            raise ArboristError(response.error_msg, response.code)
        return response.json["resources"]

    @maybe_sync
    async def grant_user_policy(self, username, policy_id):
        """
        MUST be user name, and not serial user ID
        """
        url = self._user_url + "/{}/policy".format(quote(username))
        request = {"policy": policy_id}
        response = await self.post(url, json=request, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not grant policy `{}` to user `{}`: {}".format(
                    policy_id, username, response.error_msg
                )
            )
            return None
        self.logger.info("granted policy `{}` to user `{}`".format(policy_id, username))
        return response.code

    @maybe_sync
    async def revoke_all_policies_for_user(self, username):
        url = self._user_url + "/{}/policy".format(quote(username))
        response = await self.delete(url, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not revoke policies from user `{}`: {}`".format(
                    username, response.error_msg
                )
            )
            return None
        self.logger.info("revoked all policies from user `{}`".format(username))
        return True

    @maybe_sync
    async def list_groups(self):
        response = await self.get(self._group_url)
        if response.code != 200:
            self.logger.error("could not list groups: {}".format(response.error_msg))
            raise ArboristError(response.error_msg, response.code)
        groups = response.json
        self.logger.info(
            "got arborist groups: `{}`".format(json.dumps(groups, indent=2))
        )
        return groups

    @maybe_sync
    async def create_group(self, name, users=None, policies=None):
        if users is None:
            users = []
        if policies is None:
            policies = []
        data = {"name": name, "users": users, "policies": policies}
        # Arborist doesn't handle group descriptions yet
        # if description:
        #     data["description"] = description
        response = await self.post(self._group_url, json=data)
        if response.code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warning("group `{}` already exists in arborist".format(name))
        if response.code != 201:
            self.logger.error(
                "could not create group {}: {}".format(name, response.error_msg)
            )
            return None
        self.logger.info("created new group `{}`".format(name))
        if users:
            self.logger.info("group {} contains users: {}".format(name, list(users)))
            self.logger.info("group {} has policies: {}".format(name, list(policies)))
        return response.json

    @maybe_sync
    async def put_group(self, name, description="", users=None, policies=None):
        """
        Arborist will create group if not exist and overwrite if exist.
        """
        if users is None:
            users = []
        if policies is None:
            policies = []
        data = {"name": name, "users": users, "policies": policies}
        if description:
            data["description"] = description
        response = await self.put(self._group_url, json=data)
        if not response.successful:
            msg = "could not put group `{}` in arborist: {}".format(
                name, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("put group {}".format(name))
        return response.json

    @maybe_sync
    async def delete_group(self, group_name):
        url = self._group_url + "/{}".format(quote(group_name))
        response = await self.delete(url, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not delete group `{}`: {}".format(group_name, response.error_msg)
            )
            return None
        self.logger.info("deleted group `{}`".format(group_name))
        return True

    @maybe_sync
    async def add_user_to_group(self, username, group_name, expires_at=None):
        url = self._group_url + "/{}/user".format(quote(group_name))
        request = dict(username=username)
        if expires_at:
            if hasattr(expires_at, "isoformat"):
                expires_at = expires_at.isoformat()
            request["expires_at"] = expires_at
        response = await self.post(url, json=request, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not add user `{}` to group `{}`: {}".format(
                    username, group_name, response.error_msg
                )
            )
            return None
        self.logger.info("added user `{}` to group `{}`".format(username, group_name))
        return True

    @maybe_sync
    async def remove_user_from_group(self, username, group_name):
        url = self._group_url + "/{}/user/{}".format(quote(group_name), quote(username))
        response = await self.delete(url, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not remove user `{}` from group `{}`: {}".format(
                    username, group_name, response.error_msg
                )
            )
            return None
        self.logger.info(
            "removed user `{}` from group `{}`".format(username, group_name)
        )
        return True

    @maybe_sync
    async def grant_group_policy(self, group_name, policy_id):
        url = self._group_url + "/{}/policy".format(quote(group_name))
        request = {"policy": policy_id}
        response = await self.post(url, json=request, expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not grant policy `{}` to group `{}`: {}".format(
                    policy_id, group_name, response.error_msg
                )
            )
            return None
        self.logger.info(
            "granted policy `{}` to group `{}`".format(policy_id, group_name)
        )
        return True

    @maybe_sync
    async def create_user_if_not_exist(self, username):
        self.logger.info("making sure user exists: `{}`".format(username))
        user_json = {"name": username}
        response = await self.post(self._user_url, json=user_json)
        if response.code == 409:
            return None
        if "error" in response.json:
            msg = "could not create user `{}` in arborist: {}".format(
                username, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created user {}".format(username))
        return response.json

    @maybe_sync
    async def create_client(self, client_id, policies):
        response = await self.post(
            self._client_url, json=dict(clientID=client_id, policies=policies or [])
        )
        if "error" in response.json:
            msg = "could not create client `{}` in arborist: {}".format(
                client_id, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created client {}".format(client_id))
        return response.json

    @maybe_sync
    async def update_client(self, client_id, policies):
        # retrieve existing client, create one if not found
        response = await self.get("/".join((self._client_url, quote(client_id))))
        if response.code == 404:
            res = self.create_client(client_id, policies)
            if inspect.isawaitable(res):  # handle create_client maybe_sync
                await res
            return

        # unpack the result
        if "error" in response.json:
            msg = "could not fetch client `{}` in arborist: {}".format(
                client_id, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        current_policies = set(response.json["policies"])
        policies = set(policies)

        # find newly granted policies, revoke all if needed
        url = "/".join((self._client_url, quote(client_id), "policy"))
        if current_policies.difference(policies):
            # if some policies must be removed, revoke all and re-grant later
            response = await self.delete(url)
            if response.code != 204:
                msg = (
                    "could not revoke policies "
                    "from client `{}` in arborist: {}".format(
                        client_id, response.error_msg
                    )
                )
                self.logger.error(msg)
                raise ArboristError(msg, response.code)
        else:
            # do not add policies that already exist
            policies.difference_update(current_policies)

        # grant missing policies
        for policy in policies:
            response = await self.post(url, json=dict(policy=policy), expect_json=False)
            if response.code != 204:
                msg = (
                    "could not grant policy `{}` "
                    "to client `{}` in arborist: {}".format(
                        policy, client_id, response.error_msg
                    )
                )
                self.logger.error(msg)
                raise ArboristError(msg, response.code)
        self.logger.info("updated policies for client {}".format(client_id))

    @maybe_sync
    async def delete_client(self, client_id):
        response = await self.delete(
            "/".join((self._client_url, quote(client_id))), expect_json=False
        )
        self.logger.info("deleted client {}".format(client_id))
        return response.code == 204
