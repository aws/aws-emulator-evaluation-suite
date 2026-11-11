"""cli-redshift-describe-clusters-forward-to-sqs."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-redshift-describe-clusters-forward-to-sqs"
GROUP = "cli-roundtrip"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The JSON of `aws redshift describe-clusters`, sent with `aws sqs send-message`, is received back
    unchanged by an SDK ReceiveMessage on the queue."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    # Real describe-clusters output (list may legitimately be empty -- that's fine, we're
    # testing the forwarding path, not cluster inventory).
    describe_output = _run_aws(ctx, "redshift", "describe-clusters")
    assert isinstance(describe_output, dict) and "Clusters" in describe_output, (
        f"expected `aws redshift describe-clusters` to return a JSON object with a "
        f"'Clusters' key, got: {describe_output!r}"
    )
    payload = json.dumps(describe_output, sort_keys=True)

    _run_aws(ctx, "sqs", "send-message", "--queue-url", queue_url, "--message-body", payload)

    received = _poll_receive_matching(ctx, queue_url, expected_body=payload, timeout_s=30.0)
    assert received == payload, (
        f"forwarded payload mismatch: expected the exact `aws redshift describe-clusters` "
        f"body ({len(payload)} bytes) to come back verbatim via SQS, got {received!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str -> shell=True, or argv list) with leased AWS creds + region in
    the env. Raises on non-zero exit when check=True. Returns CompletedProcess."""
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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_receive_matching(ctx, queue_url, expected_body, timeout_s=30.0, interval_s=1.0):
    """Poll receive_message until a message with exactly expected_body shows up (deleting
    everything it dequeues along the way so a retry doesn't re-observe stale state)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body == expected_body:
                return body
        time.sleep(interval_s)
    raise AssertionError(f"expected forwarded message body not observed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
