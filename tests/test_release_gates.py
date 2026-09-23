"""Release gates G235-G236.

The gateway's `/v1/info` reported version 0.5.0 through four releases,
because the number was typed into the module once. The same drift the
landing page had, in the one place a client asks the gateway what it is.
"""

from __future__ import annotations

import re
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
