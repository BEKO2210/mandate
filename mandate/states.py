"""Authorization/execution state machine. Illegal transitions raise."""

from __future__ import annotations

ALLOWED: dict[str, frozenset[str]] = {
    "PROPOSED": frozenset({"DENIED", "HUMAN_REQUIRED", "AUTHORIZED"}),
    "DENIED": frozenset(),
    "HUMAN_REQUIRED": frozenset({"AUTHORIZED", "DENIED"}),
    "AUTHORIZED": frozenset({"EXECUTING", "DENIED"}),
    "EXECUTING": frozenset({"EXECUTED", "EXECUTION_FAILED", "EXECUTION_UNKNOWN"}),
    "EXECUTED": frozenset(),
    "EXECUTION_FAILED": frozenset(),
    # Not terminal: a person who asked the upstream can settle it, and that
    # finding is signed and chained (Engine.resolve_unknown).
    "EXECUTION_UNKNOWN": frozenset({"EXECUTED", "EXECUTION_FAILED"}),
}

TERMINAL = frozenset({"DENIED", "EXECUTED", "EXECUTION_FAILED"})


class InvalidTransition(Exception):
    pass


def can_transition(src: str, dst: str) -> bool:
    return dst in ALLOWED.get(src, frozenset())


def assert_transition(src: str, dst: str) -> None:
    if not can_transition(src, dst):
        raise InvalidTransition(f"illegal transition {src} -> {dst}")
