"""e2e-message-flows-source-to-target."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-message-flows-source-to-target"
GROUP = "e2e"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe-e2e"}
_KV_TAGS = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: source/target queues + role, create+start a pipe, send a
    message to the source, observe the identical content arrive on the target,
    then stop and tear everything down."""
    source_url, source_arn = _create_queue(ctx)
    target_url, target_arn = _create_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipe-e2e-")
    _create_pipe(
        ctx,
        name,
        source_arn=source_arn,
        target_arn=target_arn,
        role_arn=role_arn,
        # Without an InputTemplate, EventBridge Pipes forwards the FULL SQS
        # record envelope (messageId/receiptHandle/body/attributes/...) as the
        # target message body -- not just the raw source body. Request just
        # the body so the target receives byte-identical content.
        target_parameters={"InputTemplate": "<$.body>"},
    )
    _wait_pipe_state(ctx, name, {"RUNNING"}, timeout_s=90.0)

    sqs = ctx.client("sqs")
    body = f"e2e-payload-{uuid.uuid4()}"
    sqs.send_message(QueueUrl=source_url, MessageBody=body)

    received = _poll_for_message_body(ctx, target_url, timeout_s=220.0)
    assert received == body, f"expected {body!r} on target queue, got {received!r}"

    pipes = ctx.client("pipes")
    pipes.stop_pipe(Name=name)
    _wait_pipe_state(ctx, name, {"STOPPED"}, timeout_s=60.0)

    pipes.delete_pipe(Name=name)
    _wait_pipe_deleted_asserted(ctx, name, timeout_s=90.0)

    resurrect_code, resurrect_msg = _client_error(lambda: pipes.start_pipe(Name=name))
    assert resurrect_code == "NotFoundException", (
        f"expected NotFoundException starting deleted pipe {name!r}, got {resurrect_code!r}"
    )
    assert resurrect_msg == f"Pipe {name} does not exist.", (
        f"unexpected StartPipe refusal message for deleted pipe {name!r}: {resurrect_msg!r}"
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
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_KV_TAGS
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
        "Tags": _RES_TAGS,
    }
    if source_parameters:
        kwargs["SourceParameters"] = source_parameters
    if target_parameters:
        kwargs["TargetParameters"] = target_parameters
    if extra_props:
        kwargs.update(extra_props)

    # IAM role trust is eventually consistent; retry CreatePipe past transient
    # ValidationException while the new role propagates (observed up to ~20s).
    deadline = time.monotonic() + 60.0
    resp = None
    last_exc = None
    while resp is None:
        try:
            resp = pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException" and time.monotonic() < deadline:
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    del last_exc

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


def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_pipe_deleted_asserted(ctx, name, timeout_s=90.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
            last_code = None
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == "NotFoundException":
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"pipe {name} was not deleted within {timeout_s}s (last describe_pipe error={last_code!r})"
    )


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
