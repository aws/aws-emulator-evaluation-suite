"""cli-redshift-sqs-missing-queue-negative."""
from __future__ import annotations

import json
import re
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-redshift-sqs-missing-queue-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI attempt to forward a Redshift-event-shaped payload to a queue URL that has been
    deleted is rejected with QueueDoesNotExist, and no message is stored anywhere; a positive
    control in the same run proves the identical forwarding call succeeds against a live queue."""
    require_tools("aws")

    sqs = ctx.client("sqs")

    fake_event_payload = json.dumps(
        {
            "Event Source": "redshift",
            "Event ID": "REDSHIFT-EVENT-1003",
            "Message": "Cluster parameter group sim2real-fake-group was created.",
        },
        sort_keys=True,
    )

    # --- positive control: the identical forwarding call against a live queue succeeds and
    # the message is observably delivered ---
    live_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=live_queue_url))

    _run_aws(
        ctx, "sqs", "send-message", "--queue-url", live_queue_url, "--message-body", fake_event_payload
    )
    delivered = _poll_receive_matching(ctx, live_queue_url, fake_event_payload, timeout_s=30.0)
    assert delivered == fake_event_payload, (
        f"expected the forwarded body to round-trip unchanged, got {delivered!r}"
    )

    # --- break exactly one thing: send the same payload to a queue that no longer exists ---
    doomed_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-doomed-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    doomed_queue_name = doomed_queue_url.rsplit("/", 1)[-1]
    sqs.delete_queue(QueueUrl=doomed_queue_url)
    _wait_until_queue_gone(ctx, doomed_queue_name, timeout_s=30.0)

    proc = _run_shell(
        ctx,
        [
            "aws",
            "--output",
            "json",
            "sqs",
            "send-message",
            "--queue-url",
            doomed_queue_url,
            "--message-body",
            fake_event_payload,
        ],
        check=False,
    )
    assert proc.returncode != 0, "sending to a deleted queue unexpectedly succeeded"
    code, msg = _cli_error(proc.stderr, "SendMessage")
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected AWS.SimpleQueueService.NonExistentQueue, got {code!r} (stderr={proc.stderr[-300:]!r})"
    )
    assert msg == "The specified queue does not exist.", msg

    # effect absent: the queue is still confirmed gone (nothing silently recreated it, and
    # there is no surviving queue anywhere that could have received the message)
    surviving = sqs.list_queues(QueueNamePrefix=doomed_queue_name).get("QueueUrls", [])
    assert not any(doomed_queue_name in url for url in surviving), (
        f"expected {doomed_queue_name!r} to be absent from ListQueues, got {surviving!r}"
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


def _wait_until_queue_gone(ctx, queue_name, timeout_s=30.0, interval_s=1.0):
    """Poll GetQueueUrl until the deleted queue's name is confirmed to no longer resolve."""
    from botocore.exceptions import ClientError

    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_url(QueueName=queue_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"):
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"queue {queue_name!r} was not confirmed deleted within {timeout_s}s")


def _cli_error(stderr: str, operation: str):
    """The (code, message) of an `aws` CLI failure, parsed from its stderr line
    'An error occurred (CODE) when calling the OPERATION operation: MESSAGE'."""
    match = re.search(
        r"An error occurred \(([\w.]+)\) when calling the " + re.escape(operation) + r" operation: (.*)",
        stderr,
    )
    if match is None:
        raise AssertionError(f"no AWS error line in the CLI stderr: {stderr[-300:]!r}")
    return match.group(1), match.group(2).strip()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
