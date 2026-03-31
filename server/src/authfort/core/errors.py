"""Auth error types — kept separate to avoid circular imports."""


class AuthError(Exception):
    """Base auth error with an error code and HTTP status."""

    def __init__(self, message: str, code: str, status_code: int = 400, **extra):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.extra = extra
        super().__init__(message)
