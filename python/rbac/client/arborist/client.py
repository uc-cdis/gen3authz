"""
Define the ArboristClient class for interfacing with the arborist service for
RBAC.
"""

from functools import wraps

import backoff
from cdislogging import get_logger
import requests

from rbac import string_types
from rbac.client.arborist.errors import (
    ArboristError,
    ArboristUnhealthyError,
    AuthZError,
)
from rbac.client.base import RBACClient


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

        try:
            self.json = response.json()
        except ValueError as e:
            if self.code != 500:
                raise ArboristError(
                    "got a confusing response from arborist, couldn't parse JSON from"
                    " response but got code {} for this response: {}"
                    .format(self.code, _escape_newlines(response.text))
                )
            self.json = {"error": {"message": str(e), "code": 500}}

    @property
    def successful(self):
        return "error" not in self.json

    @property
    def error_msg(self):
        if self.successful:
            return None
        try:
            return self.json["error"]["message"]
        except KeyError:
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


class ArboristClient(RBACClient):
    """
    A singleton class for interfacing with the RBAC engine, "arborist".
    """

    def __init__(self, logger=None, arborist_base_url="http://arborist-service/"):
        self.logger = logger or get_logger("ArboristClient")
        self._base_url = arborist_base_url.strip("/")
        self._auth_url = self._base_url + "/auth/"
        self._health_url = self._base_url + "/health"
        self._policy_url = self._base_url + "/policy/"
        self._resource_url = self._base_url + "/resource"
        self._role_url = self._base_url + "/role/"

    def healthy(self):
        """
        Indicate whether the arborist service is available and functioning.

        Return:
            bool: whether arborist service is available
        """
        try:
            response = requests.get(self._health_url)
        except requests.RequestException as e:
            self.logger.error(
                "arborist unavailable; got requests exception: {}".format(str(e))
            )
            return False
        if response.status_code != 200:
            self.logger.error(
                "arborist not healthy; {} returned code {}".format(
                    self._health_url,
                    response.status_code,
                )
            )
        return response.status_code == 200

    @_arborist_retry()
    def auth_request(self, jwt, service, method, resources):
        """
        Return:
            bool: authorization response
        """
        if isinstance(resources, string_types):
            resources = [resources]
        data = {
            "user": {"token": jwt},
            "requests": [{
                "resource": resource,
                "action": {"service": service, "method": method},
            } for resource in resources],
        }
        response = ArboristResponse(
            requests.post(self._auth_url.rstrip("/") + "/request", json=data)
        )
        if not response.successful:
            msg = "request to arborist failed: {}".format(response.json())
            raise ArboristError(message=msg, code=500)
        elif response.code == 200:
            return bool(response.json["auth"])
        else:
            # arborist could send back a 400 for things like, the user has some policy
            # that it doesn't recognize, or the request is structured incorrectly; for
            # these cases we will default to unauthorized
            msg = "arborist could not process auth request"
            detail = response.json["error"]
            self.logger.info("{}: {}".format(msg, detail))
            raise ArboristError("{}: {}".format(msg, detail))

    @_arborist_retry()
    def create_resource(self, parent_path, resource_json, overwrite=False):
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
        path = self._resource_url + parent_path
        response = ArboristResponse(requests.post(path, json=resource_json))
        if response.code == 409:
            if overwrite:
                resource_path = path + resource_json["name"]
                return self.update_resource(resource_path, resource_json)
            else:
                return None
        if not response.successful:
            self.logger.error(
                "could not create resource `{}` in arborist: {}"
                .format(path, response.error_msg)
            )
            raise ArboristError(response.error_msg)
        self.logger.info("created resource {}".format(resource_json["name"]))
        return response

    @_arborist_retry()
    def get_resource(self, path):
        """
        Return the information for a resource in arborist.

        Args:
            resource_path (str): path for the resource

        Return:
            dict: JSON representation of the resource
        """
        url = self._resource_url + path
        response = ArboristResponse(requests.get(url))
        if response.code == 404:
            return None
        if not response.successful:
            msg = response.json["error"]["message"]
            self.logger.error(msg)
            raise ArboristError(message=msg, code=500)
        return response

    @_arborist_retry()
    def update_resource(self, path, resource_json):
        url = self._resource_url + path
        response = ArboristResponse(requests.put(url, json=resource_json))
        if not response.successful:
            msg = (
                "could not update resource `{}` in arborist: {}"
                .format(path, response.json["error"]["message"])
            )
            self.logger.error(msg)
            raise ArboristError(msg)
        self.logger.info("updated resource {}".format(resource_json["name"]))
        return response

    @_arborist_retry()
    def delete_resource(self, path):
        url = self._resource_url + path
        response = requests.delete(url)
        if response.status_code not in [204, 404]:
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
            return None
        if not response.successful:
            self.logger.error(
                "could not create role `{}` in arborist: {}".format(
                    role_json["id"], response.error_msg
                )
            )
            raise ArboristError(response.json["error"])
        self.logger.info("created role {}".format(role_json["id"]))
        return response

    @_arborist_retry()
    def list_roles(self):
        return ArboristResponse(requests.get(self._role_url))

    @_arborist_retry()
    def update_role(self, role_id, role_json):
        url = self._role_url + role_id
        response = ArboristResponse(requests.put(url, json=role_json))
        if not response.successful:
            msg = (
                "could not update role `{}` in arborist: {}"
                .format(role_id, response.json["error"]["message"])
            )
            self.logger.error(msg)
            raise ArboristError(msg)
        self.logger.info("updated role {}".format(role_json["name"]))
        return response

    @_arborist_retry()
    def delete_role(self, role_id):
        response = ArboristResponse(requests.delete(self._role_url + role_id))
        if response.code >= 400:
            raise ArboristError(
                "could not delete role in arborist: {}".format(response.json()["error"])
            )

    @_arborist_retry()
    def get_policy(self, policy_id):
        """
        Return the JSON representation of a policy with this ID.
        """
        response = requests.get(self._policy_url + policy_id)
        if response.status_code == 404:
            return None
        return response.json()

    @_arborist_retry()
    def delete_policy(self, path):
        return ArboristResponse(requests.delete(self._policy_url + path))

    @_arborist_retry()
    def create_policy(self, policy_json, skip_if_exists=True):
        response = ArboristResponse(requests.post(self._policy_url, json=policy_json))
        if response.code == 409:
            return None
        if not response.successful:
            self.logger.error(
                "could not create policy `{}` in arborist: {}".format(
                    policy_json["id"], response.json["error"]["message"]
                )
            )
            raise ArboristError(response.json["error"]["message"])
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
        return ArboristResponse(requests.get(self._policy_url))

    @_arborist_retry()
    def update_policy(self, policy_id, policy_json):
        url = self._policy_url + policy_id
        response = ArboristResponse(requests.put(url, json=policy_json))
        if not response.successful:
            msg = (
                "could not update policy `{}` in arborist: {}"
                .format(policy_id, response.json["error"]["message"])
            )
            self.logger.error(msg)
            raise ArboristError(msg)
        self.logger.info("updated policy {}".format(policy_json["name"]))
        return response
