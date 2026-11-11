"""cli-missing-queue-policy-blocks-delivery-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-missing-queue-policy-blocks-delivery-workflow"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A confirmed SNS to SQS subscription delivers nothing while the queue policy grants SNS no
    sqs:SendMessage; applying the policy with the CLI lets the next publish arrive."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"), Tags=_resource_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # Same-account SQS endpoints auto-confirm regardless of the queue's access policy —
    # confirm that first so the negative below is attributable to the missing policy,
    # not to a pending/unconfirmed subscription.
    attrs = _poll_subscription_confirmed(ctx, sub_arn)
    assert attrs.get("PendingConfirmation") == "false", (
        f"subscription {sub_arn} did not reach PendingConfirmation=false "
        f"(got {attrs.get('PendingConfirmation')!r}); a still-pending subscription would make the "
        "negative below indistinguishable from an unconfirmed-subscription block"
    )

    marker_blocked = ctx.unique_name("blocked-")
    sns.publish(TopicArn=topic_arn, Message=marker_blocked)
    assert not _wait_for_marker(ctx, queue_url, marker_blocked, timeout_s=25.0), (
        "message was delivered to the queue despite it having no access policy "
        "granting sns.amazonaws.com sqs:SendMessage"
    )

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
    _poll_policy_applied(ctx, queue_url, topic_arn)

    marker_allowed = ctx.unique_name("allowed-")
    sns.publish(TopicArn=topic_arn, Message=marker_allowed)
    assert _wait_for_marker(ctx, queue_url, marker_allowed, timeout_s=30.0), (
        "message was still not delivered after granting the queue policy (positive control failed)"
    )


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


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
    return attrs


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
