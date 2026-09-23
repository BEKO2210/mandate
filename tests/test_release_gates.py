"""Release gates G235-G236 and G253-G254.

The gateway's `/v1/info` reported version 0.5.0 through four releases,
because the number was typed into the module once. The same drift the
landing page had, in the one place a client asks the gateway what it is.

And the README told people to `pip install "mandate[mcp]"`, while the PyPI
project named `mandate` is an unrelated AWS Cognito wrapper: following the
instructions installed someone else's code. Until the project owns a name on
PyPI, every install line points at the repository.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from fastapi.testclient import TestClient

import mandate
from mandate.auth import OpenAccess
from mandate.engine import Engine
from mandate.gateway import create_app
from mandate.keys import PersistedDevKeyProvider
from mandate.store import Store


def test_g235_the_gateway_reports_the_version_it_is(tmp_path):
    engine = Engine(Store(tmp_path / "obj"), key_provider=PersistedDevKeyProvider(tmp_path / "k"))
    info = TestClient(create_app(engine, auth=OpenAccess())).get("/v1/info").json()
    assert info["version"] == mandate.__version__


def test_g236_readme_and_changelog_name_the_shipped_version():
    version = mandate.__version__
    readme = Path("README.md").read_text(encoding="utf-8").splitlines()[0]
    assert readme == f"# Mandate v{version}", readme
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    newest = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M)
    assert newest and newest.group(1) == version, "the newest changelog entry is another version"
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert f'\nversion = "{version}"\n' in pyproject


REPO = "git+https://github.com/BEKO2210/mandate"


def _pypi_mandate_targets(line: str) -> list[str]:
    """The arguments of a `pip install` line that would fetch `mandate` from
    PyPI. Only the command counts: a repository URL in a trailing comment
    does not change what pip resolves."""
    command = line.split("pip install", 1)[1]
    # The command ends where the prose, markup or shell comment around it starts.
    command = re.split(r"`|<|\s#", command, maxsplit=1)[0]
    # A quote left open belongs to the string the line sits in (a Python
    # constant, say); trim it. What still does not parse is split on spaces,
    # which can only flag more, never less.
    args = command.split()
    while command:
        try:
            args = shlex.split(command)
            break
        except ValueError:
            if command[-1] not in "'\")`,.;":
                break
            command = command[:-1]
    bad, editable = [], False
    for arg in args:
        if arg in ("-e", "--editable"):
            editable = True
            continue
        if arg.startswith("-"):
            continue
        if "mandate" in arg.lower() and REPO not in arg and not editable:
            bad.append(arg)
        editable = False
    return bad


def test_g253_no_install_line_resolves_mandate_from_pypi():
    """`pip install mandate…` without a direct reference asks PyPI for a name
    this project does not own. Every argument that installs Mandate names the
    repository (or is a local checkout installed with -e) instead."""
    # The check reads the argument, not the line.
    assert _pypi_mandate_targets(f"pip install mandate  # {REPO}") == ["mandate"]
    assert _pypi_mandate_targets(f'pip install "mandate[mcp]" "other @ {REPO}"') == ["mandate[mcp]"]
    assert _pypi_mandate_targets(f'pip install "mandate[mcp] @ {REPO}"') == []
    assert _pypi_mandate_targets('pip install -e "./mandate[mcp]"') == []
    assert _pypi_mandate_targets(f"""INSTALL = 'pip install "mandate[mcp] @ {REPO}"'""") == []
    assert _pypi_mandate_targets("""INSTALL = 'pip install "mandate[mcp]"'""") == ["mandate[mcp]"]

    sources = [Path("README.md"), Path("site/index.html"), *Path("docs").glob("*.md"), *Path("mandate").rglob("*.py")]
    bad, found = [], 0
    for path in sources:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "pip install" not in line or "mandate" not in line.split("pip install", 1)[1]:
                continue
            found += 1
            if _pypi_mandate_targets(line):
                bad.append(f"{path}: {line.strip()}")
    assert not bad, "install lines that would fetch `mandate` from PyPI:\n" + "\n".join(bad)
    assert found, "the documentation must say how to install"


def test_g254_the_release_workflow_holds_no_token():
    """A token in the repository or its secrets is a credential that outlives
    the release it was made for. Publishing, when it comes, uses Trusted
    Publishing; until then the workflow uploads nothing."""
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    for leak in ("password:", "PYPI_TOKEN", "PYPI_API_TOKEN", "${{ secrets."):
        assert leak not in workflow, leak
    assert "twine check --strict" in workflow and "/tmp/clean/bin/mandate demo" in workflow
