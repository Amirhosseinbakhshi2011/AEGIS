"""AEGIS custom exceptions."""

from __future__ import annotations


class AegisError(Exception):
    """Base exception for AEGIS."""

    def __init__(self, message: str, *, code: str = "aegis_error") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class SecurityViolationError(AegisError):
    """Raised when a security policy is violated (SSRF, private IP, scope escape)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="security_violation")


class AuthorizationError(AegisError):
    """Raised when the user is not authorized for the requested action."""

    def __init__(self, message: str = "Not authorized") -> None:
        super().__init__(message, code="authorization_error")


class DomainNotVerifiedError(AegisError):
    """Raised when a domain has not been verified for scanning."""

    def __init__(self, domain: str) -> None:
        super().__init__(
            f"Domain '{domain}' is not verified. Complete domain ownership verification first.",
            code="domain_not_verified",
        )


class ScanLimitExceededError(AegisError):
    """Raised when scan budget or rate limits are exceeded."""

    def __init__(self, message: str = "Scan limit exceeded") -> None:
        super().__init__(message, code="scan_limit_exceeded")


class ScanCancelledError(AegisError):
    """Raised when a scan is cancelled by the user or system."""

    def __init__(self, scan_id: str) -> None:
        super().__init__(f"Scan {scan_id} was cancelled", code="scan_cancelled")


class ConfigurationError(AegisError):
    """Raised for invalid configuration."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="configuration_error")
