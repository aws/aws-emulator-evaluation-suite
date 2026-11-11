"""pipe-target-permission-missing-delivery-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipe-target-permission-missing-delivery-rejected"
GROUP = "server-side"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe"}
_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


# timing:real-time — visibility: 30 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A pipe whose role can read the source but cannot SendMessage to the target never delivers
    (the message stays on the source), while a sibling pipe with full permissions delivers."""
    # --- broken pipe: role missing sqs:SendMessage on the target ---
    bad_source_url, bad_source_arn = _create_queue(ctx)
    bad_target_url, bad_target_arn = _create_queue(ctx)
    bad_role_arn = _create_role_with_statements(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": bad_source_arn,
            }
            # deliberately no sqs:SendMessage grant on bad_target_arn
        ],
    )
    bad_name = ctx.unique_name("sim2real-pipe-noperm-")
    _create_pipe(
        ctx,
        bad_name,
        source_arn=bad_source_arn,
        target_arn=bad_target_arn,
        role_arn=bad_role_arn,
        source_parameters={"SqsQueueParameters": {"BatchSize": 1}},
    )
    _wait_pipe_state(ctx, bad_name, {"RUNNING"}, timeout_s=90.0)

    sqs = ctx.client("sqs")
    bad_body = f"blocked-payload-{uuid.uuid4()}"
    sqs.send_message(QueueUrl=bad_source_url, MessageBody=bad_body)

    leaked = _poll_for_message_body(ctx, bad_target_url, timeout_s=45.0)
    assert leaked is None, f"message delivered to target despite missing SendMessage permission: {leaked!r}"

    # Still present on the source (visible or in flight for retry). The default 30s visibility
    # timeout means polling across a retry cycle and demanding presence at every sample.
    _retry_window_deadline = time.monotonic() + 35.0
    _presence_samples = 0
    while time.monotonic() < _retry_window_deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=bad_source_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        still_present = int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])
        assert still_present >= 1, (
            f"source message vanished even though delivery to the target should have failed "
            f"(sample {_presence_samples})"
        )
        _presence_samples += 1
        time.sleep(5.0)
    assert _presence_samples >= 2, (
        f"expected multiple presence samples across the visibility-timeout retry window, got {_presence_samples}"
    )

    # --- positive control: identical setup with the SendMessage grant; delivery succeeds. ---
    good_source_url, good_source_arn = _create_queue(ctx)
    good_target_url, good_target_arn = _create_queue(ctx)
    good_role_arn = _create_role_with_statements(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": good_source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": good_target_arn},
        ],
    )
    good_name = ctx.unique_name("sim2real-pipe-perm-ok-")
    _create_pipe(
        ctx,
        good_name,
        source_arn=good_source_arn,
        target_arn=good_target_arn,
        role_arn=good_role_arn,
        source_parameters={"SqsQueueParameters": {"BatchSize": 1}},
        target_parameters={"InputTemplate": "<$.body>"},
    )
    _wait_pipe_state(ctx, good_name, {"RUNNING"}, timeout_s=90.0)

    good_body = f"delivered-payload-{uuid.uuid4()}"
    sqs.send_message(QueueUrl=good_source_url, MessageBody=good_body)
    delivered = _poll_for_message_body(ctx, good_target_url, timeout_s=220.0)
    assert delivered == good_body, f"positive control failed to deliver: expected {good_body!r}, got {delivered!r}"


_TERMINAL_FAILURE_STATES = {
    "CREATE_FAILED",
    "START_FAILED",
    "UPDATE_FAILED",
    "DELETE_FAILED",
    "CREATE_ROLLBACK_FAILED",
    "DELETE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_FAILED",
}

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_queue(ctx, fifo=False):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipe-q-")
    kwargs = {"QueueName": f"{name}.fifo" if fifo else name, "tags": _RES_TAGS}
    if fifo:
        kwargs["Attributes"] = {"FifoQueue": "true", "ContentBasedDeduplication": "true"}
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_role_with_statements(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipe-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_TAGS)["Role"]
    policy_name = "pipe-access"
    policy_doc = json.dumps({"Version": "2012-10-17", "Statement": statements})
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_pipe(
    ctx,
    name,
    source_arn,
    target_arn,
    role_arn,
    source_parameters=None,
    target_parameters=None,
    desired_state="RUNNING",
    extra_props=None,
):
    pipes = ctx.client("pipes")
    kwargs = {
        "Name": name,
        "Source": source_arn,
        "Target": target_arn,
        "RoleArn": role_arn,
        "DesiredState": desired_state,
        "Tags": _RES_TAGS,
    }
    if source_parameters:
        kwargs["SourceParameters"] = source_parameters
    if target_parameters:
        kwargs["TargetParameters"] = target_parameters
    if extra_props:
        kwargs.update(extra_props)

    deadline = time.monotonic() + 60.0
    resp = None
    while resp is None:
        try:
            resp = pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise

    def _cleanup():
        try:
            desc = pipes.describe_pipe(Name=name)
            if desc["CurrentState"] not in ("STOPPED", "CREATE_FAILED"):
                try:
                    pipes.stop_pipe(Name=name)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NotFoundException":
                        raise
                try:
                    _wait_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED", "STOP_FAILED"}, timeout_s=60.0)
                except AssertionError:
                    pass
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            pipes.delete_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        _wait_pipe_deleted(ctx, name, timeout_s=60.0)

    ctx.on_cleanup(_cleanup)
    return resp


def _wait_pipe_state(ctx, name, states, timeout_s=90.0, interval_s=4.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in states:
            return desc
        if last in _TERMINAL_FAILURE_STATES:
            raise AssertionError(f"pipe {name} entered failure state {last}: {desc.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} did not reach {states} within {timeout_s}s (last={last})")


def _wait_pipe_deleted(ctx, name, timeout_s=60.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3.0)


def _poll_for_message_body(ctx, queue_url, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
        time.sleep(1.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
