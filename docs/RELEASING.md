# Releasing

1. Merge the release PR. It sets the same version in `pyproject.toml`,
   `mandate/__init__.py`, the README title, the newest `CHANGELOG.md` entry and
   the site; the gates refuse a mismatch.
2. *Releases → Draft a new release*: tag `vX.Y.Z` on `main`, title `vX.Y.Z`,
   notes from the CHANGELOG entry. *Publish release*.
3. *Actions → Release build* runs on its own: the tag must equal the pyproject
   version, the full suite runs, the distribution is built and checked with
   `twine check --strict`, the wheel is installed into a clean environment and
   `mandate demo` runs from it. The built files are attached to the run.

## PyPI

Not yet. The PyPI project named `mandate` is an unrelated package, and this
project's name is still being decided. Until then the only install is from
the repository:

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
```

Once the name is settled, publishing is added as one job in the same
workflow, through PyPI Trusted Publishing: PyPI trusts this workflow, in this
repository, in a protected `pypi` environment, and nothing else. No API token
is ever created or stored — G254 refuses one in the workflow.
