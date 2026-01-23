"""
VVP Verifier custom exceptions.
Maps parsing/validation errors to structured error codes per §4.2A.
"""

from app.vvp.api_models import ErrorCode


class VVPIdentityError(Exception):
    """Exception for VVP-Identity header parsing errors.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    The caller is responsible for converting this to ErrorDetail.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "VVPIdentityError":
        """Factory for VVP_IDENTITY_MISSING error."""
        return cls(
            code=ErrorCode.VVP_IDENTITY_MISSING,
            message="VVP-Identity header is missing or empty"
        )

    @classmethod
    def invalid(cls, reason: str) -> "VVPIdentityError":
        """Factory for VVP_IDENTITY_INVALID error."""
        return cls(
            code=ErrorCode.VVP_IDENTITY_INVALID,
            message=f"VVP-Identity header is invalid: {reason}"
        )
