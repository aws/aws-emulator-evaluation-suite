"""What a check file needs from its runner, read statically: tools, Python packages, notes.

A runner lacking a tool reports the check ``tool_missing``; one lacking a package leaves the check
``unloadable`` (imported at the top) or a ``runner_fault`` (imported in ``run``). Neither is scored,
and listing both before a run keeps a sweep from losing checks to them.
"""

import ast
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

from fidelity_tests_runner.budget import tools_in
from fidelity_tests_runner.harness import KNOWN_TOOLS

#: Import name -> the pip distribution that provides it, where the two differ or need extras.
DISTRIBUTIONS = {
    "PIL": "pillow",
    "amazondax": "amazon-dax-client",
    "aws_cdk": "aws-cdk-lib",
    "awsiot": "awsiotsdk",
    "cassandra": "cassandra-driver",
    "cassandra_sigv4": "cassandra-sigv4",
    "gremlin_python": "gremlinpython",
    "kafka": "kafka-python",
    "opensearchpy": "opensearch-py",
    "paho": "paho-mqtt",
    "psycopg": "psycopg[binary]",
    "pymysql": "PyMySQL",
    "requests_aws4auth": "requests-aws4auth",
    "sagemaker": "sagemaker-core",
    "websocket": "websocket-client",
    "yaml": "PyYAML",
}

#: Modules this package provides or installs, so never a dependency of a check.
_PROVIDED = frozenset(
    {"fidelity_tests_runner", "behavioral_harness", "boto3", "botocore", "certifi"}
)


def _imports(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def _tools(tree: ast.Module) -> set[str]:
    """``require_tools("x", ...)`` arguments, plus known tools a subprocess argv starts with."""
    found = set(tools_in(tree))
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and first.value in KNOWN_TOOLS:
                found.add(first.value)
    return found


def _reads_deployments(tree: ast.Module) -> bool:
    """Whether the file opens its ``deployments/`` directory: ``<path> / "deployments"``, or a
    path string starting ``deployments/``. An API field named ``deployments`` is neither."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Div)
            and isinstance(node.right, ast.Constant)
            and node.right.value == "deployments"
        ):
            return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("deployments/")
        ):
            return True
    return False


def requirements_of(path: Path) -> dict[str, Any]:
    """``{file, tools, python_packages, missing_tools, missing_python_packages, notes}``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    third_party = sorted(m for m in _imports(tree) - _PROVIDED if m not in sys.stdlib_module_names)
    tools = sorted(_tools(tree))
    notes = []
    if _reads_deployments(tree) and not (path.parent / "deployments").is_dir():
        notes.append("needs deployments/ beside it, which is absent")
    return {
        "file": str(path),
        "tools": tools,
        "python_packages": [DISTRIBUTIONS.get(m, m) for m in third_party],
        "missing_tools": [t for t in tools if shutil.which(t) is None],
        "missing_python_packages": [
            DISTRIBUTIONS.get(m, m) for m in third_party if importlib.util.find_spec(m) is None
        ],
        "notes": notes,
    }
