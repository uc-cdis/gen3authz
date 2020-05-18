import abc
import six


class AuthzClient(six.with_metaclass(abc.ABCMeta)):
    """
    Abstract class to define behavior of an authz client implementation.
    """

    @abc.abstractmethod
    def healthy(self):
        """Indicate whether the authz service is available."""

    @abc.abstractmethod
    def auth_request(self, jwt, service, method, resource):
        pass

    @abc.abstractmethod
    def create_resource(self, parent_path, resource_json, overwrite=False):
        pass

    @abc.abstractmethod
    def get_resource(self, resource_path):
        pass

    @abc.abstractmethod
    def update_resource(self, path, resource_json):
        pass

    @abc.abstractmethod
    def delete_resource(self, path):
        pass

    @abc.abstractmethod
    def list_policies(self):
        pass

    @abc.abstractmethod
    def policies_not_exist(self, policy_ids):
        pass

    @abc.abstractmethod
    def create_role(self, role_json):
        pass

    @abc.abstractmethod
    def list_roles(self):
        pass

    @abc.abstractmethod
    def update_role(self, role_id, role_json):
        pass

    @abc.abstractmethod
    def delete_role(self, role_id):
        pass

    @abc.abstractmethod
    def create_policy(self, policy_json, skip_if_exists=True):
        pass

    @abc.abstractmethod
    def get_policy(self, policy_id):
        pass

    @abc.abstractmethod
    def update_policy(self, policy_id, policy_json):
        pass

    @abc.abstractmethod
    def delete_policy(self, policy_id):
        pass
