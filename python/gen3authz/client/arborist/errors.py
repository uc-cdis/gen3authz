from cdiserrors import APIError, InternalError, AuthZError


class ArboristError(APIError):
    """Generic exception related to problems with arborist."""

    def __init__(self, message=None, code=500):
        self.message = message or "Arborist error"
        self.code = code
        self.json = {"error": self.message, "code": self.code}


class ArboristUnhealthyError(InternalError, ArboristError):
    """Exception raised to signify the arborist service is unresponsive."""

    def __init__(self, message=None):
        super(ArboristUnhealthyError, self).__init__()
        self.message = message or "could not reach arborist service"
        self.code = 500
        self.json = {"error": self.message, "code": self.code}
