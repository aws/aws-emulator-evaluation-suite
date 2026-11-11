"""cli-sqs-set-queue-policy-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sqs-set-queue-policy-workflow"
GROUP = "cli-workflow"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws cli sets a queue policy allowing sns:SendMessage from a topic ARN; a
    subsequent SNS publish is then actually delivered to the queue."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"), Tags=[{"Key": "sim2real", "Value": "true"}]
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
    _run_aws(
        ctx,
        "sqs", "set-queue-attributes",
        "--queue-url", queue_url,
        "--attributes", json.dumps({"Policy": json.dumps(policy)}),
    )

    applied = _poll_policy_applied(ctx, queue_url, topic_arn)
    assert topic_arn in applied, (
        f"queue policy set via CLI never showed the subscribed topic {topic_arn!r} in "
        f"GetQueueAttributes(Policy) after polling; last read: {applied!r}"
    )

    marker = ctx.unique_name("policy-marker-")
    sns.publish(TopicArn=topic_arn, Message=marker)
    delivered = _wait_for_marker(ctx, queue_url, marker, timeout_s=40.0)
    assert delivered, "message was not delivered after the queue policy was applied via CLI"


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
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]).get(
            "Attributes", {}
        )
        policy_text = attrs.get("Policy", "")
        if needle in policy_text:
            return policy_text
        time.sleep(2)
    return policy_text


def _wait_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 30.0) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            text = body.get("Message") if isinstance(body, dict) else body
            if text == marker:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
