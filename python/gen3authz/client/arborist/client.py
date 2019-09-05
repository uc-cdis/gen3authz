"""
Define the ArboristClient class for interfacing with the arborist service for
authz.
"""

from functools import wraps

try:
    import urllib.parse as urllib
except ImportError:
    import urllib

import backoff
from cdislogging import get_logger
import requests

from gen3authz import string_types
from gen3authz.client.arborist.errors import (
    ArboristError,
    ArboristUnhealthyError,
    AuthZError,
)
from gen3authz.client.base import AuthzClient


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
                    " response but got code {} for this response: {}"
                    .format(self.code, _escape_newlines(response.text)),
                    self.code
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


def _arborist_retry(*backoff_args, **backoff_kwargs):
    """
    Decorate an ``ArboristClient`` method to retry requests to arborist, if arborist
    says it's unhealthy. By default, it will retry requests up to 5 times, waiting for a
    maximum of 10 seconds, before giving up and declaring arborist unavailable.
    """
    # set some defaults for when to give up: after 5 failures, or 10 seconds (these can
    # be overridden by keyword arguments)
    if "max_tries" not in backoff_kwargs:
        backoff_kwargs["max_tries"] = 5
    if "max_time" not in backoff_kwargs:
        backoff_kwargs["max_time"] = 10

    def decorator(method):
        def giveup():
            raise ArboristUnhealthyError()

        def wait_gen():
            # shorten the wait times between retries a little to fit our scale a little
            # better (aim to give up within 10 s)
            for n in backoff.fibo():
                yield n / 2.0

        @wraps(method)
        def wrapper(self, *m_args, **m_kwargs):
            do_backoff = backoff.on_predicate(
                wait_gen, on_giveup=giveup, *backoff_args, **backoff_kwargs
            )
            do_backoff(self.healthy)
            return method(self, *m_args, **m_kwargs)

        return wrapper

    return decorator


class ArboristClient(AuthzClient):
    """
    A singleton class for interfacing with the authz engine, "arborist".
    """

    def __init__(self, logger=None, arborist_base_url="http://arborist-service/"):
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

    def healthy(self):
        """
        Indicate whether the arborist service is available and functioning.

        Return:
            bool: whether arborist service is available
        """
        try:
            response = ArboristResponse(requests.get(self._health_url), expect_json=False)
        except requests.RequestException as e:
            self.logger.error(
                "arborist unavailable; got requests exception: {}".format(str(e))
            )
            return False
        if response.code != 200:
            self.logger.error(
                "arborist not healthy; {} returned code {}".format(
                    self._health_url,
                    response.code,
                )
            )
        return response.code == 200

    @_arborist_retry()
    def auth_mapping(self, username):
        """
        For given user, get mapping from the resources that this user can access
        to the actions on those resources for which they are authorized.

        Return:
            dict: response JSON from arborist
        """
        data = {
            "username": username,
        }
        response = ArboristResponse(
            requests.post(self._auth_url.rstrip("/") + "/mapping", json=data)
        )
        if not response.successful:
            raise ArboristError(response.error_msg)
        return response.json

    @_arborist_retry()
    def auth_request(self, jwt, service, methods, resources):
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
            "requests": [{
                "resource": resource,
                "action": {"service": service, "method": method},
            } for resource in resources for method in methods],
        }
        response = ArboristResponse(
            requests.post(self._auth_url.rstrip("/") + "/request", json=data)
        )
        if not response.successful:
            msg = "request to arborist failed: {}".format(response.error_msg)
            raise ArboristError(msg, response.code)
        elif response.code == 200:
            return bool(response.json["auth"])
        else:
            # arborist could send back a 400 for things like, the user has some policy
            # that it doesn't recognize, or the request is structured incorrectly; for
            # these cases we will default to unauthorized
            msg = "arborist could not process auth request: {}".format(response.error_msg)
            self.logger.info(msg)
            raise ArboristError(msg, response.code)

    @_arborist_retry()
    def create_resource(self, parent_path, resource_json, create_parents=False):
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

        path = self._resource_url + urllib.quote(parent_path)
        if create_parents:
            path = path + "?p"

        response = ArboristResponse(requests.post(path, json=resource_json))
        if response.code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warning(
                "resource `{}` already exists in arborist".format(resource_json["name"])
            )
            return None
        if not response.successful:
            msg = "could not create resource `{}` in arborist: {}".format(path, response.error_msg)
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created resource {}".format(resource_json["name"]))
        return response.json

    @_arborist_retry()
    def get_resource(self, path):
        """
        Return the information for a resource in arborist.

        Args:
            resource_path (str): path for the resource

        Return:
            dict: JSON representation of the resource
        """
        url = self._resource_url + urllib.quote(path)
        response = ArboristResponse(requests.get(url))
        if response.code == 404:
            return None
        if not response.successful:
            self.logger.error(response.error_msg)
            raise ArboristError(response.error_msg, response.code)
        return response

    @_arborist_retry()
    def update_resource(self, path, resource_json, create_parents=False):
        url = self._resource_url + urllib.quote(path)
        if create_parents:
            url = url + "?p"
        response = ArboristResponse(requests.put(url, json=resource_json))
        if not response.successful:
            msg = (
                "could not update resource `{}` in arborist: {}"
                .format(path, response.error_msg)
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("updated resource {}".format(resource_json["name"]))
        return response.json

    @_arborist_retry()
    def delete_resource(self, path):
        url = self._resource_url + urllib.quote(path)
        response = ArboristResponse(requests.delete(url))
        if response.code not in [204, 404]:
            raise ArboristError
        return True

    @_arborist_retry()
    def policies_not_exist(self, policy_ids):
        """
        Return any policy IDs which do not exist in arborist. (So, if the
        result is empty, all provided IDs were valid.)

        Return:
            list: policies (if any) that don't exist in arborist
        """
        existing_policies = self.list_policies().get["policies"]
        return [
            policy_id for policy_id in policy_ids if policy_id not in existing_policies
        ]

    @_arborist_retry()
    def create_role(self, role_json):
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
        response = ArboristResponse(requests.post(self._role_url, json=role_json))
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

    @_arborist_retry()
    def list_roles(self):
        return ArboristResponse(requests.get(self._role_url))

    @_arborist_retry()
    def update_role(self, role_id, role_json):
        url = self._role_url + urllib.quote(role_id)
        response = ArboristResponse(requests.put(url, json=role_json))
        if not response.successful:
            msg = (
                "could not update role `{}` in arborist: {}"
                .format(role_id, response.error_msg)
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("updated role {}".format(role_json["name"]))
        return response

    @_arborist_retry()
    def delete_role(self, role_id):
        response = ArboristResponse(requests.delete(self._role_url + urllib.quote(role_id)))
        if response.code == 404:
            # already doesn't exist, this is fine
            return
        elif response.code >= 400:
            msg = "could not delete role in arborist: {}".format(response.error_msg)
            self.logger.error(msg)
            raise ArboristError(msg, response.code)

    @_arborist_retry()
    def get_policy(self, policy_id):
        """
        Return the JSON representation of a policy with this ID.
        """
        response = ArboristResponse(requests.get(self._policy_url + urllib.quote(policy_id)))
        if response.code == 404:
            return None
        return response.json

    @_arborist_retry()
    def delete_policy(self, path):
        return ArboristResponse(requests.delete(self._policy_url + urllib.quote(path))).json

    @_arborist_retry()
    def create_policy(self, policy_json, skip_if_exists=True):
        response = ArboristResponse(requests.post(self._policy_url, json=policy_json))
        if response.code == 409:
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
        return response

    @_arborist_retry()
    def list_policies(self):
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
        return ArboristResponse(requests.get(self._policy_url)).json


    def update_policy(self, policy_json):
        # Appease abstract base class
        put_policy(policy_json)

    @_arborist_retry()
    def put_policy(self, policy_json):
        """
        Arborist will create policy if not exist and overwrite if exist.
        """
        url = self._policy_url + urllib.quote(policy_json["id"])
        response = ArboristResponse(requests.put(url, json=policy_json))
        if not response.successful:
            msg = (
                "could not put policy `{}` in arborist: {}"
                .format(policy_json["id"], response.error_msg)
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("put policy {}".format(policy_json["id"]))
        return response


    @_arborist_retry()
    def create_user(self, user_info):
        """
        Args:
            user_info (dict):
                user information that goes in the request to arborist; see arborist docs
                for required field names. notably it's `name` not `username`
        """
        if "name" not in user_info:
            raise ValueError("create_user requires username `name` in user info")
        response = ArboristResponse(requests.post(self._user_url, json=user_info))
        if response.code == 409:
            # already exists
            return
        elif response.code != 201:
            self.logger.error(response.error_msg)


    @_arborist_retry()
    def list_resources_for_user(self, username):
        """
        Args:
            username (str)

        Return:
            List[str]: list of resource paths which the user has any access to
        """
        url = "{}/{}/resources".format(self._user_url, urllib.quote(username))
        response = ArboristResponse(requests.get(url))
        if response.code != 200:
            raise ArboristError(response.error_msg, response.code)
        return response.json["resources"]


    @_arborist_retry()
    def grant_user_policy(self, username, policy_id):
        """
        MUST be user name, and not serial user ID
        """
        url = self._user_url + "/{}/policy".format(urllib.quote(username))
        request = {"policy": policy_id}
        response = ArboristResponse(requests.post(url, json=request), expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not grant policy `{}` to user `{}`: {}".format(
                    policy_id, username, response.error_msg
                )
            )
            return None
        self.logger.info("granted policy `{}` to user `{}`".format(policy_id, username))
        return response.code

    @_arborist_retry()
    def revoke_all_policies_for_user(self, username):
        url = self._user_url + "/{}/policy".format(urllib.quote(username))
        response = ArboristResponse(requests.delete(url), expect_json=False)
        if response.code != 204:
            self.logger.error(
                "could not revoke policies from user `{}`: {}`".format(username, response.error_msg)
            )
            return None
        self.logger.info("revoked all policies from user `{}`".format(username))
        return True

    @_arborist_retry()
    def create_group(
        self, name, description="", users=[], policies=[]
    ):
        data = {"name": name, "users": users, "policies": policies}
        if description:
            data["description"] = description
        response = ArboristResponse(requests.post(self._group_url, json=data))
        if response.code == 409:
            # already exists; this is ok, but leave warning
            self.logger.warn("group `{}` already exists in arborist".format(name))
        if response.code != 201:
            self.logger.error("could not create group {}: {}".format(name, response.error_msg))
            return None
        self.logger.info("created new group `{}`".format(name))
        if users:
            self.logger.info("group {} contains users: {}".format(name, list(users)))
            self.logger.info("group {} has policies: {}".format(name, list(policies)))
        return response.json

    @_arborist_retry()
    def put_group(self, name, description="", users=[], policies=[]):
        """
        Arborist will create group if not exist and overwrite if exist.
        """
        data = {"name": name, "users": users, "policies": policies}
        if description:
            data["description"] = description
        response = ArboristResponse(requests.put(self._group_url, json=data))
        if not response.successful:
            msg = (
                "could not put group `{}` in arborist: {}"
                .format(name, response.error_msg)
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("put group {}".format(name))
        return response.json

    @_arborist_retry()
    def grant_group_policy(self, group_name, policy_id):
        url = self._group_url + "/{}/policy".format(urllib.quote(group_name))
        request = {"policy": policy_id}
        response = ArboristResponse(requests.post(url, json=request), expect_json=False)
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

    @_arborist_retry()
    def create_user_if_not_exist(self, username):
        self.logger.info("making sure user exists: `{}`".format(username))
        user_json = {"name": username}
        response = ArboristResponse(requests.post(self._user_url, json=user_json))
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

    @_arborist_retry()
    def create_client(self, client_id, policies):
        response = ArboristResponse(requests.post(
            self._client_url, json=dict(clientID=client_id, policies=policies or [])
        ))
        if "error" in response.json:
            msg = "could not create client `{}` in arborist: {}".format(
                client_id, response.error_msg
            )
            self.logger.error(msg)
            raise ArboristError(msg, response.code)
        self.logger.info("created client {}".format(client_id))
        return response.json

    @_arborist_retry()
    def update_client(self, client_id, policies):
        # retrieve existing client, create one if not found
        response = ArboristResponse(requests.get("/".join((self._client_url, urllib.quote(client_id)))))
        if response.code == 404:
            self.create_client(client_id, policies)
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
        url = "/".join((self._client_url, urllib.quote(client_id), "policy"))
        if current_policies.difference(policies):
            # if some policies must be removed, revoke all and re-grant later
            response = ArboristResponse(requests.delete(url))
            if response.code != 204:
                msg = "could not revoke policies from client `{}` in arborist: {}".format(client_id, response.error_msg)
                self.logger.error(msg)
                raise ArboristError(msg, response.code)
        else:
            # do not add policies that already exist
            policies.difference_update(current_policies)

        # grant missing policies
        for policy in policies:
            response = ArboristResponse(requests.post(url, json=dict(policy=policy)), expect_json=False)
            if response.code != 204:
                msg = "could not grant policy `{}` to client `{}` in arborist: {}".format(
                    policy, client_id, response.error_msg
                )
                self.logger.error(msg)
                raise ArboristError(msg, response.code)
        self.logger.info("updated policies for client {}".format(client_id))

    @_arborist_retry()
    def delete_client(self, client_id):
        response = ArboristResponse(requests.delete("/".join((self._client_url, urllib.quote(client_id)))), expect_json=False)
        self.logger.info("deleted client {}".format(client_id))
        return response.code == 204
