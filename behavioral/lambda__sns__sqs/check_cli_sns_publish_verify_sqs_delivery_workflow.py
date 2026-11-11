"""cli-sns-publish-verify-sqs-delivery-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sns-publish-verify-sqs-delivery-workflow"
GROUP = "cli-workflow"
SERVICES = ["lambda", "sns", "sqs"]
_SCENARIO = "cli-sns-publish-verify-sqs-delivery-workflow"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An `aws sns publish` CLI call results in the exact message body — and its
    MessageId — becoming visible via SDK sqs.receive_message on the subscribed queue."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"),
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

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

    marker = ctx.unique_name("cli-publish-")
    published = _run_aws(ctx, "sns", "publish", "--topic-arn", topic_arn, "--message", marker)
    cli_message_id = published["MessageId"]

    envelope = _wait_for_envelope(ctx, queue_url, marker, timeout_s=40.0)
    assert envelope is not None, "CLI-published message never arrived on the subscribed queue"
    assert envelope["Message"] == marker, (
        f"delivered body mismatch: expected {marker!r}, got {envelope['Message']!r}"
    )
    assert envelope["MessageId"] == cli_message_id, (
        "delivered MessageId does not match the CLI publish response: "
        f"expected {cli_message_id!r}, got {envelope['MessageId']!r}"
    )
    assert envelope["TopicArn"] == topic_arn, (
        f"delivered TopicArn mismatch: expected {topic_arn!r}, got {envelope['TopicArn']!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS credentials + region in the
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
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS credentials configured."""

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
    return policy_text


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
