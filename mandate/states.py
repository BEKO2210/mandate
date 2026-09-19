from __future__ import annotations

ALLOWED = {
    "PROPOSED": frozenset({"DENIED", "HUMAN_REQUIRED", "AUTHORIZED"}),
    "DENIED": frozenset(),
    "HUMAN_REQUIRED": frozenset({"AUTHORIZED", "DENIED"}),
    "AUTHORIZED": frozenset({"EXECUTING", "DENIED"}),
    "EXECUTING": frozenset({"EXECUTED", "EXECUTION_FAILED", "EXECUTION_UNKNOWN"}),
    "EXECUTED": frozenset(),
    "EXECUTION_FAILED": frozenset(),
    "EXECUTION_UNKNOWN": frozenset(),
}

class InvalidTransition(Exception):
    pass

def can_transition(src, dst):
    return dst in ALLOWED.get(src, frozenset())

def assert_transition(src, dst):
    if not can_transition(src, dst):
        raise InvalidTransition(f"illegal transition {src} -> {dst}")
