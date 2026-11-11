"""cli-sqs-create-send-receive-delete."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-sqs-create-send-receive-delete"

GROUP = "cli-roundtrip"

SERVICES = ["sqs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Full SQS lifecycle via pure CLI: create-queue, send, receive, delete — then prove
    the deleted queue is gone and unusable via an independent SDK read."""
    name = _xname(ctx, "q")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    queue_url = f"{ctx.client('sqs').meta.endpoint_url}/{acct}/{name}"
    sqs = ctx.client("sqs")
    ctx.on_cleanup(lambda: _delete_queue_if_exists(sqs, queue_url))

    result = _run_script(
        ctx,
        f"""
        QUEUE_URL=$(aws sqs create-queue --queue-name {name} --tags '{json.dumps(_xsvc_resource_tags())}' --query QueueUrl --output text)
        aws sqs send-message --queue-url "$QUEUE_URL" --message-body '{{"source":"cli"}}' > /dev/null
        BODY=$(aws sqs receive-message --queue-url "$QUEUE_URL" --query 'Messages[0].Body' --output text)
        echo "$BODY"
        aws sqs delete-queue --queue-url "$QUEUE_URL"
    """,
    )
    body = result.stdout.strip()
    assert body == '{"source":"cli"}', (
        f'Expected round-tripped body \'{{"source":"cli"}}\', got: {body!r}'
    )

    # The script's own delete-queue above is unasserted otherwise: prove the queue
    # is gone via an independent read, and that a mutation against the dead id also fails.
    try:
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        raise AssertionError(f"Expected {queue_url} to be gone after delete-queue")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "AWS.SimpleQueueService.NonExistentQueue", (
            f"Expected NonExistentQueue reading deleted queue, got: {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "The specified queue does not exist.", (
            f"Expected 'The specified queue does not exist.' reading deleted queue, got: {message!r}"
        )
    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody="post-delete")
        raise AssertionError(
            f"Expected send-message on deleted queue {queue_url} to fail"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "AWS.SimpleQueueService.NonExistentQueue", (
            f"Expected NonExistentQueue sending to deleted queue, got: {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "The specified queue does not exist.", (
            f"Expected 'The specified queue does not exist.' sending to deleted queue, got: {message!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_queue_if_exists(sqs, queue_url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


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
