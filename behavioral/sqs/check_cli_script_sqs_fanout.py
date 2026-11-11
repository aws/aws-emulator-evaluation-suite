"""cli-script-sqs-fanout."""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any

from behavioral_harness import tags

CHECK = "cli-script-sqs-fanout"

GROUP = "cli-script"

SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Bash script sends N messages then drains and counts them."""
    queue = _create_queue(ctx)
    result = _run_script(
        ctx,
        f"""
        QUEUE_URL="{queue["url"]}"
        for i in $(seq 1 5); do
            aws sqs send-message --queue-url "$QUEUE_URL" --message-body "item-$i" > /dev/null
        done
        COUNT=0
        for attempt in $(seq 1 10); do
            MSGS=$(aws sqs receive-message --queue-url "$QUEUE_URL" --max-number-of-messages 10 --wait-time-seconds 2 --output json 2>/dev/null)
            if [ -z "$MSGS" ] || [ "$MSGS" = "" ]; then MSGS='{{}}'; fi
            N=$(echo "$MSGS" | python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{{}}'); print(len(d.get('Messages',[])))")
            if [ "$N" = "0" ]; then break; fi
            COUNT=$((COUNT + N))
            echo "$MSGS" | python3 -c "
import sys, json, subprocess, os
data = sys.stdin.read()
if data.strip():
    msgs = json.loads(data).get('Messages', [])
    for m in msgs:
        print('BODY:' + m['Body'])
        subprocess.run(['aws', 'sqs', 'delete-message', '--queue-url', '$QUEUE_URL', '--receipt-handle', m['ReceiptHandle']], check=True, capture_output=True, env=dict(os.environ))
"
        done
        DEPTH=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names ApproximateNumberOfMessages --query 'Attributes.ApproximateNumberOfMessages' --output text)
        echo "DEPTH:$DEPTH"
        echo "COUNT:$COUNT"
    """,
    )
    lines = result.stdout.strip().split("\n")
    bodies = [line[len("BODY:") :] for line in lines if line.startswith("BODY:")]
    depth_lines = [line[len("DEPTH:") :] for line in lines if line.startswith("DEPTH:")]
    count_lines = [line[len("COUNT:") :] for line in lines if line.startswith("COUNT:")]
    assert count_lines, f"no COUNT line in script output: {result.stdout!r}"
    count = int(count_lines[-1])
    assert count == 5, f"Expected 5 messages drained, got {count}"
    expected_bodies = {f"item-{i}" for i in range(1, 6)}
    assert set(bodies) == expected_bodies, (
        f"Expected drained bodies {sorted(expected_bodies)}, got {sorted(bodies)}"
    )
    assert depth_lines, f"no DEPTH line in script output: {result.stdout!r}"
    depth = depth_lines[-1]
    assert depth == "0", (
        f"Expected queue depth 0 after drain (independent GetQueueAttributes read), got {depth!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


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
