"""Error types for authkeeper."""


class AuthKeeperError(Exception):
    """Raised for any recoverable failure in an authkeeper operation.

    All public functions raise this (and only this) on failure so callers --
    including the CLI and the GUI -- have a single exception to catch.  In
    particular a wrong passphrase surfaces as this error with a generic
    message and never leaks any part of the vault plaintext.
    """
