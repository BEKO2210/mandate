"""Mandate — Identity + Permission + Transaction OS for AI agents."""

from .auth import DEFAULT_TENANT, LedgerApiKeyAuth, OpenAccess, RateLimiter, issue_api_key
from .crypto import KeyPair, sign_object, verify_object
from .engine import Engine
from .models import AgentCard, Constraint, Grant, Intent, Principal
from .policy import evaluate

__version__ = "0.5.0"
__all__ = [
    "Engine",
    "OpenAccess",
    "LedgerApiKeyAuth",
    "RateLimiter",
    "issue_api_key",
    "DEFAULT_TENANT",
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
