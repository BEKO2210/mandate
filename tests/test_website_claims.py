"""The landing page makes checkable claims. This checks them.

The site said "218 gates passing" while the suite had 222. Nobody lied —
the number was written by hand once and then the suite grew. That is the
ordinary way a page drifts, and it is the reason the number has to be
derived rather than typed.

It matters more here than on most projects. Mandate's whole argument is
that a claim should be verifiable against evidence rather than believed.
A page that advertises the number of checks, and is itself unchecked, is
the argument failing at the first place a visitor could test it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

SITE = Path("site/index.html")
TESTS = Path("tests")


def count_gates() -> int:
    """Every module-level `test_*` function across the suite.

    "Gate" in this project means one test function — they are named G001
    upwards and each one is a single scenario. No module uses
    `pytest.mark.parametrize`, so this count and pytest's collected count
    are the same number; if that ever changes, this gate fails and the
    disagreement has to be settled deliberately rather than silently.
    """
    total = 0
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        total += sum(
            1 for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        )
    return total


def test_the_page_states_the_real_number_of_gates():
    html = SITE.read_text(encoding="utf-8")
    actual = count_gates()

    claimed = [int(n) for n in re.findall(r"(\d+)\s+gates passing", html)]
    assert claimed, "the page should say how many gates back it up"
    for number in claimed:
        assert number == actual, (
            f"the page advertises {number} gates and the suite has {actual}"
        )

    in_terminal = [int(n) for n in re.findall(r"(\d+)\s+passed", html)]
    assert in_terminal, "the hardening terminal should show the suite result"
    for number in in_terminal:
        assert number == actual, (
            f"the terminal block shows {number} passed and the suite has {actual}"
        )


def test_every_gate_the_page_names_exists():
    """A page that cites G193 should be citing something real."""
    html = SITE.read_text(encoding="utf-8")
    named = set(re.findall(r"\bG(\d{3})\b", html))
    assert named, "the hardening block should name the gates it points at"

    defined = "".join(
        path.read_text(encoding="utf-8") for path in sorted(TESTS.glob("test_*.py"))
    )
    for gate in sorted(named):
        assert f"def test_g{gate}" in defined, f"the page names G{gate}, which does not exist"


def test_the_page_states_the_shipped_version():
    """Three releases went out while the page still said v0.5.0.

    Only the two places that claim *what this is* are pinned: the nav badge
    and the footer line. The body legitimately refers to older releases —
    the chain section is headed "v0.7.0 – v0.8.0" and should be. An earlier
    version of this gate asserted that no other version string appears
    anywhere, which failed on correct content: a test that forbids the truth
    is not a stricter test, it is a wrong one.
    """
    import mandate

    html = SITE.read_text(encoding="utf-8")
    badge = re.search(r'<span class="ver">v([\d.]+)</span>', html)
    footer = re.search(r"Mandate v([\d.]+) ·", html)
    assert badge and footer, "the nav badge and the footer should name the version"
    assert badge.group(1) == mandate.__version__, (
        f"the nav badge says v{badge.group(1)}, the package is v{mandate.__version__}"
    )
    assert footer.group(1) == mandate.__version__, (
        f"the footer says v{footer.group(1)}, the package is v{mandate.__version__}"
    )
