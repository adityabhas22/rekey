"""Browser adapters — Chrome CDP attach + custom actions security boundary."""

from rekey.adapters.browser.actions import WrongOriginError, build_controller, verify_origin
from rekey.adapters.browser.chrome_cdp import CDPConfig, ChromeCDPSession
from rekey.adapters.browser.rotation_driver import BrowserUseRotationDriver
from rekey.adapters.browser.secret_store import (
    RotationSecrets,
    SecretNotFound,
    SecretStore,
)

__all__ = [
    "BrowserUseRotationDriver",
    "CDPConfig",
    "ChromeCDPSession",
    "RotationSecrets",
    "SecretNotFound",
    "SecretStore",
    "WrongOriginError",
    "build_controller",
    "verify_origin",
]
