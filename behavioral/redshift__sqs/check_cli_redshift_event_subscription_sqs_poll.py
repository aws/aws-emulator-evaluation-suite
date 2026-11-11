"""cli-redshift-event-subscription-sqs-poll."""
from __future__ import annotations

import json
import re
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-redshift-event-subscription-sqs-poll"
GROUP = "cli-workflow"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI-created Redshift event subscription relays REDSHIFT-EVENT-1003 (cluster parameter
    group created) through SNS to SQS, observed by polling `aws sqs receive-message`."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    redshift = ctx.client("redshift")

    # --- wire the SNS -> SQS delivery path (SDK; the notification transport, not under test) ---
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-").replace("_", "-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
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

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # --- CLI creates the Redshift event subscription against that SNS topic ---
    subscription_name = ctx.unique_name("sim2real-behav-").lower().rstrip("-")
    _run_aws(
        ctx,
        "redshift",
        "create-event-subscription",
        "--subscription-name",
        subscription_name,
        "--sns-topic-arn",
        topic_arn,
        "--source-type",
        "cluster-parameter-group",
        "--event-categories",
        "configuration",
        "--severity",
        "INFO",
        "--tags",
        f"Key=sim2real-check,Value={CHECK}",
    )
    ctx.on_cleanup(
        lambda: redshift.delete_event_subscription(SubscriptionName=subscription_name)
    )

    # --- trigger a qualifying, low-cost action: creating a cluster parameter group fires
    # REDSHIFT-EVENT-1003 "Cluster parameter group [name] was created." under category
    # "configuration" -- no billable cluster is provisioned. ---
    param_group_name = ctx.unique_name("sim2real-behav-").lower().rstrip("-")
    _run_aws(
        ctx,
        "redshift",
        "create-cluster-parameter-group",
        "--parameter-group-name",
        param_group_name,
        "--parameter-group-family",
        "redshift-1.0",
        "--description",
        "sim2real behavioral fidelity check",
        "--tags",
        f"Key=sim2real-check,Value={CHECK}",
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster_parameter_group(ParameterGroupName=param_group_name)
    )

    # --- CLI polling loop against SQS: confirm the relayed notification arrives ---
    matched = _poll_cli_for_event(
        ctx, queue_url, needle=param_group_name, timeout_s=280.0, wait_time_s=20
    )
    assert matched is not None, (
        f"no SNS-relayed Redshift event mentioning parameter group {param_group_name!r} "
        f"was observed on the queue within the poll window"
    )
    # REDSHIFT-EVENT-1003 as relayed through SNS: a JSON event whose message names the group
    # and the creation minute.
    event = json.loads(matched)
    assert event.get("Event Source") == "cluster-parameter-group" and event.get("Resource") == param_group_name, (
        f"expected a cluster-parameter-group event for {param_group_name!r}, got: {matched!r}"
    )
    pattern = re.escape(f"Cluster parameter group '{param_group_name}' was created at ") + (
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\."
    )
    assert re.fullmatch(pattern, event.get("Event Message", "")), (
        f"expected the REDSHIFT-EVENT-1003 message for {param_group_name!r}, got: {event.get('Event Message')!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str -> shell=True, or argv list) with the run's AWS creds + region in
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


def _poll_cli_for_event(ctx, queue_url, needle, timeout_s=280.0, wait_time_s=20):
    """Repeatedly long-poll SQS via the CLI for a message whose SNS-enveloped body mentions
    `needle`; deletes every message it dequeues (matched or not) so retries don't re-observe
    stale state. Returns the inner SNS Message text on match, else None."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = _run_aws(
            ctx,
            "sqs",
            "receive-message",
            "--queue-url",
            queue_url,
            "--max-number-of-messages",
            "10",
            "--wait-time-seconds",
            str(wait_time_s),
        )
        messages = resp.get("Messages", []) if isinstance(resp, dict) else []
        for msg in messages:
            body_raw = msg["Body"]
            try:
                envelope = json.loads(body_raw)
                inner = envelope.get("Message", body_raw)
            except (json.JSONDecodeError, ValueError):
                inner = body_raw
            _run_aws(
                ctx,
                "sqs",
                "delete-message",
                "--queue-url",
                queue_url,
                "--receipt-handle",
                msg["ReceiptHandle"],
            )
            if needle in inner:
                return inner
        time.sleep(2.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
