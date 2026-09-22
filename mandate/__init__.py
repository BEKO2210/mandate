"""Mandate — Identity + Permission + Transaction OS for AI agents."""

from .auth import DEFAULT_TENANT, LedgerApiKeyAuth, LedgerRateLimiter, OpenAccess, RateLimiter, issue_api_key
from .crypto import KeyPair, sign_object, verify_object
from .engine import Engine
from .models import AgentCard, Constraint, Grant, Intent, Principal
from .chain import ChainReport, verify_chain
from .policy import evaluate
from .signing import Signer, SigningError, signer_from_config

__version__ = "0.8.1"
__all__ = [
    "Engine",
    "OpenAccess",
    "LedgerApiKeyAuth",
    "LedgerRateLimiter",
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
    "ChainReport",
    "verify_chain",
    "sign_object",
    "Signer",
    "SigningError",
    "signer_from_config",
    "verify_object",
]
