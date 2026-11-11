"""The environment an emulator run executes check code and tools in: an allowlist and its pins.

``isolated`` applies it to ``os.environ`` for a run's scope and restores the environment after;
``subprocess_env`` builds a tool's environment from the same allowlist.
Checks assert, so a Python that strips assertions (``-O``, ``PYTHONOPTIMIZE``) is refused.
A test file run directly has already run its top-level code when ``isolated`` begins.
"""

import os
import shutil
import sys
import tempfile
import threading
import urllib.request
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from fidelity_tests_runner.trust import bundle_env

NO_PROXY = "localhost,127.0.0.1,::1"
#: Tool configuration files pinned empty: kubectl's, git's, Terraform's, npm's and netrc's.
EMPTY_TOOL_CONFIG = (
    "KUBECONFIG",
    "GIT_CONFIG_GLOBAL",
    "TF_CLI_CONFIG_FILE",
    "NPM_CONFIG_USERCONFIG",
    "NETRC",
)

#: The allowlist every process of an emulator run inherits from, besides every ``LC_*``: where its
#: programs, runtimes and locale are. A CLI or IaC subprocess gets identity, endpoint, region,
#: trust, home and temp from the run.
SUBPROCESS_ENV = frozenset(
    {
        "PATH",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "XDG_RUNTIME_DIR",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_CONTEXT",
        "JAVA_HOME",
        "NODE_PATH",
        "LD_LIBRARY_PATH",
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONUNBUFFERED",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
    }
)
#: What the run's own process keeps beyond ``SUBPROCESS_ENV``: its home, temp directory and region.
PROCESS_ENV = SUBPROCESS_ENV | {"HOME", "TMPDIR", "AWS_REGION", "AWS_DEFAULT_REGION"}
#: The run's own inputs, which an operator sets for the run and the runner and tests read.
RUN_PREFIXES = ("FIDELITY_TESTS_",)


class OptimizedPython(RuntimeError):
    """Python strips assertions, so every fidelity test would pass."""


def refuse_optimized() -> None:
    """Raise :class:`OptimizedPython` under ``-O`` or ``PYTHONOPTIMIZE``."""
    if sys.flags.optimize:
        raise OptimizedPython(
            "Python runs with assertions stripped (-O or PYTHONOPTIMIZE); fidelity tests assert, "
            "so every test would pass"
        )


def _pins(verify: bool | str) -> dict[str, str]:
    """What an emulator run sets: no config, metadata, proxy or telemetry, and its trust bundle."""
    env = dict.fromkeys(("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"), os.devnull)
    env.update(dict.fromkeys(EMPTY_TOOL_CONFIG, os.devnull))
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    # The SAM CLI turns telemetry on at its first run in a HOME that has no SAM config, which a
    # test's private HOME never has.
    env["SAM_CLI_TELEMETRY"] = "0"
    env["NO_PROXY"] = env["no_proxy"] = NO_PROXY
    env.update(bundle_env(verify))
    return env


def emulator_env(base: Mapping[str, str], verify: bool | str = True) -> dict[str, str]:
    """``PROCESS_ENV``, ``LC_*`` and the run's inputs from ``base``, with the run's pins."""
    return _allowlisted(base, verify, PROCESS_ENV, ("LC_", *RUN_PREFIXES))


def subprocess_env(base: Mapping[str, str], verify: bool | str = True) -> dict[str, str]:
    """``SUBPROCESS_ENV`` and ``LC_*`` from ``base``, with the run's pins; nothing else."""
    return _allowlisted(base, verify, SUBPROCESS_ENV, ("LC_",))


def _allowlisted(
    base: Mapping[str, str], verify: bool | str, names: frozenset[str], prefixes: tuple[str, ...]
) -> dict[str, str]:
    """The variables of ``base`` that ``names`` or ``prefixes`` allow, then the run's pins."""
    env = {k: v for k, v in base.items() if k in names or k.startswith(prefixes)}
    env.update(_pins(verify))
    return env


_lock = threading.Lock()
_state: dict = {"depth": 0, "saved": None, "opener": None, "verify": None, "docker": None}


@contextmanager
def isolated(verify: bool | str = True) -> Iterator[None]:
    """Run the block in :func:`emulator_env` and an empty private ``DOCKER_CONFIG``; restore after.

    Nested blocks share the outermost one's environment, so another ``verify`` raises ValueError.
    Raises :class:`OptimizedPython` first.
    """
    refuse_optimized()
    with _lock:
        if _state["depth"] and _state["verify"] != verify:
            raise ValueError(
                f"a nested isolated() block trusts {verify!r}, the open one {_state['verify']!r}"
            )
        if _state["depth"] == 0:
            docker = tempfile.mkdtemp(prefix="fidelity-tests-docker-")
            _state["verify"] = verify
            _state["saved"] = dict(os.environ)
            target = emulator_env(os.environ, verify)
            for name in set(os.environ) - set(target):
                del os.environ[name]
            os.environ.update(target)
            _state["docker"] = os.environ["DOCKER_CONFIG"] = docker
            # urlopen builds its default opener, and that opener's TLS context, once per process.
            _state["opener"] = getattr(urllib.request, "_opener", None)
            urllib.request.install_opener(None)
        _state["depth"] += 1
    try:
        yield
    finally:
        with _lock:
            _state["depth"] -= 1
            if _state["depth"] == 0:
                saved = _state["saved"]
                for name in set(os.environ) - set(saved):
                    del os.environ[name]
                os.environ.update(saved)
                shutil.rmtree(_state["docker"], ignore_errors=True)
                _state["saved"] = _state["verify"] = _state["docker"] = None
                urllib.request.install_opener(_state["opener"])
                _state["opener"] = None
