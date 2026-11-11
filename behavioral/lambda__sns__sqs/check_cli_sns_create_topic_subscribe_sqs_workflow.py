"""cli-sns-create-topic-subscribe-sqs-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sns-create-topic-subscribe-sqs-workflow"
GROUP = "cli-workflow"
SERVICES = ["lambda", "sns", "sqs"]


_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CLI-created topic subscription of a queue is confirmed with the right topic and endpoint,
    is listed, and delivers a CLI-published message with the same MessageId to the queue."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags=_managed_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    topic_name = ctx.unique_name("sim2real-topic-")
    created = _run_aws(ctx, "sns", "create-topic", "--name", topic_name, "--tags",
                        f"Key={_MANAGED_TAG_KEY},Value=true")
    topic_arn = created["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    _poll_policy_applied(ctx, queue_url, topic_arn)

    subscribed = _run_aws(
        ctx,
        "sns", "subscribe",
        "--topic-arn", topic_arn,
        "--protocol", "sqs",
        "--notification-endpoint", queue_arn,
        "--return-subscription-arn",
    )
    sub_arn = subscribed["SubscriptionArn"]
    assert "PendingConfirmation" not in sub_arn, (
        f"expected --return-subscription-arn to hand back a real ARN for an sqs-protocol "
        f"subscribe, got the placeholder {sub_arn!r}"
    )
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    attrs = _poll_subscription_confirmed(ctx, sub_arn)
    assert attrs.get("PendingConfirmation") == "false", (
        f"expected PendingConfirmation=false for an sqs-protocol subscription, "
        f"got {attrs.get('PendingConfirmation')!r} for {sub_arn}"
    )
    assert attrs.get("TopicArn") == topic_arn, (
        f"expected subscription {sub_arn} to report TopicArn={topic_arn!r}, "
        f"got {attrs.get('TopicArn')!r}"
    )
    assert attrs.get("Endpoint") == queue_arn, (
        f"expected subscription {sub_arn} to report Endpoint={queue_arn!r}, "
        f"got {attrs.get('Endpoint')!r}"
    )

    listed = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert any(s["SubscriptionArn"] == sub_arn for s in listed), (
        f"expected {sub_arn!r} in ListSubscriptionsByTopic({topic_arn!r}), "
        f"got {[s['SubscriptionArn'] for s in listed]!r}"
    )

    marker = ctx.unique_name("cli-sub-confirm-")
    published = _run_aws(ctx, "sns", "publish", "--topic-arn", topic_arn, "--message", marker)
    cli_message_id = published["MessageId"]

    envelope = _wait_for_envelope(ctx, queue_url, marker, timeout_s=40.0)
    assert envelope is not None, (
        f"expected message {marker!r} (MessageId={cli_message_id!r}) published via the CLI "
        f"to arrive on the subscribed queue {queue_url!r} within 40s, but it never did — the "
        f"subscription reported Confirmed but is not actually wired for delivery"
    )
    assert envelope.get("MessageId") == cli_message_id, (
        f"expected the delivered envelope's MessageId to match the CLI publish's "
        f"{cli_message_id!r}, got {envelope.get('MessageId')!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with leased AWS creds + region in the
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


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with leased AWS creds configured."""

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


def _poll_subscription_confirmed(ctx, sub_arn: str, timeout_s: float = 30.0) -> dict:
    sns = ctx.client("sns")
    deadline = time.monotonic() + timeout_s
    attrs: dict = {}
    while time.monotonic() < deadline:
        attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
        if attrs.get("PendingConfirmation") == "false":
            return attrs
        time.sleep(2)
    raise AssertionError(
        f"subscription {sub_arn} did not reach PendingConfirmation=false within "
        f"{timeout_s}s; last observed attributes: {attrs!r}"
    )


def _poll_policy_applied(ctx, queue_url: str, needle: str, timeout_s: float = 30.0) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    policy_text = ""
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])[
            "Attributes"
        ]
        policy_text = attrs.get("Policy", "")
        if needle in policy_text:
            return policy_text
        time.sleep(2)
    raise AssertionError(
        f"queue {queue_url} policy never came to include {needle!r} within {timeout_s}s; "
        f"last observed policy: {policy_text!r}"
    )


def _wait_for_envelope(ctx, queue_url: str, marker: str, timeout_s: float = 40.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict) and body.get("Message") == marker:
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
