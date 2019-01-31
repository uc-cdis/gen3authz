from cdiserrors import APIError, InternalError, AuthZError


class ArboristError(APIError):
    pass


class ArboristUnhealthyError(InternalError, ArboristError):
    """Exception raised to signify the arborist service is unresponsive."""

    def __init__(self, message=None):
        super(ArboristUnhealthyError, self).__init__()
        self.message = message or "could not reach arborist service"
        self.code = 500
        self.json = {"error": self.message, "code": self.code}
