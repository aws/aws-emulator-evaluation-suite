"""cli-query-jmespath-filter."""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-query-jmespath-filter"

GROUP = "cli-query"

SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """--query applies a JMESPath filter expression ([?...]) to a list result."""
    require_tools("aws")
    sqs = ctx.client("sqs")
    prefix = _xname(ctx, "q")
    urls = {}
    for suffix in ("alpha", "beta", "target"):
        name = f"{prefix}-{suffix}"
        url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
        urls[suffix] = url
        ctx.on_cleanup(lambda url=url: sqs.delete_queue(QueueUrl=url))

    # ListQueues can lag CreateQueue; poll briefly until all three are visible.
    all_urls: list[str] = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        all_urls = sqs.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])
        if len(all_urls) >= 3:
            break
        time.sleep(1)
    assert len(all_urls) == 3, (
        f"Expected 3 queues under prefix {prefix!r}, got {all_urls}"
    )

    # A JMESPath filter expression ([?...]) narrows the list result to the one match.
    filtered = _run_aws(
        ctx,
        "sqs",
        "list-queues",
        "--queue-name-prefix",
        prefix,
        "--query",
        "QueueUrls[?ends_with(@, 'target')]",
    )
    assert filtered == [urls["target"]], f"Expected [{urls['target']}], got {filtered}"

    # The same filter on a suffix that matches nothing narrows to empty, not to everything.
    unmatched = _run_aws(
        ctx,
        "sqs",
        "list-queues",
        "--queue-name-prefix",
        prefix,
        "--query",
        "QueueUrls[?ends_with(@, 'no-such-suffix')]",
    )
    assert unmatched == [], f"Expected no matches, got {unmatched}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
