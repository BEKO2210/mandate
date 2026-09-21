"""Mandate — Identity + Permission + Transaction OS for AI agents."""

from .crypto import KeyPair, sign_object, verify_object
from .engine import Engine
from .models import AgentCard, Constraint, Grant, Intent, Principal
from .policy import evaluate

__version__ = "0.3.0"
__all__ = [
    "Engine",
    "KeyPair",
    "Principal",
    "AgentCard",
    "Grant",
    "Intent",
    "Constraint",
    "evaluate",
    "sign_object",
    "verify_object",
]
