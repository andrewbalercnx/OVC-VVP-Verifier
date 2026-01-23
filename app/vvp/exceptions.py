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


class PassportError(Exception):
    """Exception for PASSporT JWT parsing/validation errors.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    The caller is responsible for converting this to ErrorDetail.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "PassportError":
        """Factory for PASSPORT_MISSING error."""
        return cls(
            code=ErrorCode.PASSPORT_MISSING,
            message="PASSporT JWT is missing or empty"
        )

    @classmethod
    def parse_failed(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_PARSE_FAILED error.

        Used for:
        - Malformed JWT structure
        - Invalid base64/JSON
        - Missing required fields
        - Binding violations (ppt/kid mismatch, iat drift, exp mismatch)
        """
        return cls(
            code=ErrorCode.PASSPORT_PARSE_FAILED,
            message=f"PASSporT parse failed: {reason}"
        )

    @classmethod
    def forbidden_alg(cls, alg: str) -> "PassportError":
        """Factory for PASSPORT_FORBIDDEN_ALG error."""
        return cls(
            code=ErrorCode.PASSPORT_FORBIDDEN_ALG,
            message=f"PASSporT uses forbidden algorithm: {alg}"
        )

    @classmethod
    def expired(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_EXPIRED error.

        Used only for actual expiry policy failures:
        - Token expired (now > exp + clock_skew)
        - Validity window exceeded (exp - iat > max_validity)
        - Max-age exceeded when exp absent

        NOT used for binding violations (use parse_failed instead).
        """
        return cls(
            code=ErrorCode.PASSPORT_EXPIRED,
            message=f"PASSporT expired: {reason}"
        )
