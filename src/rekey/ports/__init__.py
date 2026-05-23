"""Port (interface) definitions — the seams of the application."""

from rekey.ports.breach_check import BreachChecker
from rekey.ports.event_bus import EventBus
from rekey.ports.handoff import HandoffDecision, HandoffOutcome, HandoffUI
from rekey.ports.llm import LLMFactory
from rekey.ports.otp import OTPFetcher
from rekey.ports.rotation_driver import LockoutDetected, RotationDriver, RotationDriverError
from rekey.ports.vault import CredentialNotFound, VaultReader, VaultWriter

__all__ = [
    "BreachChecker",
    "CredentialNotFound",
    "EventBus",
    "HandoffDecision",
    "HandoffOutcome",
    "HandoffUI",
    "LLMFactory",
    "LockoutDetected",
    "OTPFetcher",
    "RotationDriver",
    "RotationDriverError",
    "VaultReader",
    "VaultWriter",
]
