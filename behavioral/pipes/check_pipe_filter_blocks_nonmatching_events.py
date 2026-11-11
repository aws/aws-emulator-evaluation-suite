"""pipe-filter-blocks-nonmatching-events."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipe-filter-blocks-nonmatching-events"
GROUP = "server-side"
SERVICES = ["pipes"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe with FilterCriteria forwards only messages whose body matches the pattern, and
    CreatePipe with a malformed (invalid JSON) pattern is rejected with ValidationException."""
    source_url, source_arn = _create_queue(ctx)
    target_url, target_arn = _create_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    bad_name = ctx.unique_name("sim2real-pipe-filter-bad-")
    pipes = ctx.client("pipes")
    try:
        pipes.create_pipe(
            Name=bad_name,
            Source=source_arn,
            Target=target_arn,
            RoleArn=role_arn,
            DesiredState="STOPPED",
            SourceParameters={
                "SqsQueueParameters": {"BatchSize": 1},
                "FilterCriteria": {"Filters": [{"Pattern": "{not-valid-json"}]},
            },
            Tags=_RES_TAGS,
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException for malformed FilterCriteria pattern, "
            f"got {exc.response['Error']['Code']}"
        )
        expected_msg = json.dumps(
            {
                "ValidationErrorFields": [
                    {
                        "Name": "Pattern",
                        "Message": "Invalid Event Pattern. Reason: Unexpected character ('n' (code 110)): "
                        "was expecting double-quote to start field name.",
                    }
                ]
            },
            separators=(",", ":"),
        )
        assert exc.response["Error"].get("Message") == expected_msg, (
            f"expected {expected_msg!r}, got {exc.response['Error'].get('Message')!r}"
        )
    else:
        ctx.on_cleanup(lambda: pipes.delete_pipe(Name=bad_name))
        raise AssertionError("CreatePipe accepted a malformed (non-JSON) FilterCriteria pattern")

    name = ctx.unique_name("sim2real-pipe-filter-")
    pattern = json.dumps({"body": {"type": ["match-me"]}})
    _create_pipe(
        ctx,
        name,
        source_arn=source_arn,
        target_arn=target_arn,
        role_arn=role_arn,
        source_parameters={
            "SqsQueueParameters": {"BatchSize": 1},
            "FilterCriteria": {"Filters": [{"Pattern": pattern}]},
        },
        target_parameters={"InputTemplate": "<$.body.id>"},
        extra_props={"Tags": _RES_TAGS},
    )
    _wait_pipe_state(ctx, name, {"RUNNING"}, timeout_s=90.0)

    sqs = ctx.client("sqs")

    # The pipe drops filtered SQS messages; a generous bounded poll must see nothing.
    nomatch_id = str(uuid.uuid4())
    nomatch_body = json.dumps({"type": "no-match", "id": nomatch_id})
    sqs.send_message(QueueUrl=source_url, MessageBody=nomatch_body)
    leaked = _poll_for_message_body(ctx, target_url, timeout_s=40.0)
    assert leaked is None, f"non-matching message leaked onto target: {leaked!r}"

    # Positive control, same pipe. Once FilterCriteria parses `body` as JSON, Pipes re-emits
    # nested-object paths unquoted, so the template extracts the scalar id field.
    match_id = str(uuid.uuid4())
    match_body = json.dumps({"type": "match-me", "id": match_id})
    sqs.send_message(QueueUrl=source_url, MessageBody=match_body)
    delivered = _poll_for_message_body(ctx, target_url, timeout_s=200.0)
    assert delivered == match_id, f"expected matching message id {match_id!r}, got {delivered!r}"

    desc = ctx.client("pipes").describe_pipe(Name=name)
    assert desc["CurrentState"] == "RUNNING", (
        f"expected pipe {name} to remain RUNNING after delivering the positive control, "
        f"got {desc['CurrentState']!r}"
    )


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

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe-filter"}
_RES_TAGS_KV = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


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


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipe-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_RES_TAGS_KV
    )["Role"]
    policy_name = "pipe-access"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": source_arn,
                },
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
            ],
        }
    )
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
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if desc["CurrentState"] not in ("STOPPED", "CREATE_FAILED", "STOP_FAILED", "START_FAILED"):
            if desc["CurrentState"] != "STOPPING":
                pipes.stop_pipe(Name=name)
            _wait_pipe_state(ctx, name, {"STOPPED", "STOP_FAILED"}, timeout_s=120.0)
        pipes.delete_pipe(Name=name)
        _wait_pipe_deleted(ctx, name, timeout_s=120.0)

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
    raise AssertionError(f"pipe {name} was not deleted within {timeout_s}s")


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
