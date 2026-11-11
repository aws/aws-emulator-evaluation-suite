"""enrichment-input-template-json-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enrichment-input-template-json-round-trip"
GROUP = "representation"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe-tmpl"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipe's TargetParameters.InputTemplate containing nested JSON with a
    high-precision numeric literal is stored and returned byte-identical by
    DescribePipe (it is an opaque template string, not a re-parsed number)."""
    source_url, source_arn = _create_queue(ctx)
    target_url, target_arn = _create_queue(ctx)
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    # Deliberately more significant digits than an IEEE-754 double can hold,
    # to prove the template is preserved as raw text, not round-tripped
    # through a floating point representation.
    input_template = (
        '{"orderId": "<$.body.orderId>", '
        '"preciseValue": 123456789012345678901234567890.123456789012345678901234567890, '
        '"nested": {"list": [1, 2, 3], "flag": true, "note": "unicode-\u03a9"}}'
    )

    name = ctx.unique_name("sim2real-pipe-tmpl-")
    _create_pipe(
        ctx,
        name,
        source_arn=source_arn,
        target_arn=target_arn,
        role_arn=role_arn,
        desired_state="STOPPED",
        target_parameters={"InputTemplate": input_template},
    )
    desc = _wait_pipe_state(ctx, name, {"STOPPED"}, timeout_s=90.0)

    stored_template = desc["TargetParameters"]["InputTemplate"]
    assert stored_template == input_template, (
        f"InputTemplate round-trip mismatch:\nsent={input_template!r}\ngot={stored_template!r}"
    )

    # Re-describe independently to make sure it isn't just an artifact of the
    # create response.
    desc2 = ctx.client("pipes").describe_pipe(Name=name)
    got2 = desc2["TargetParameters"]["InputTemplate"]
    assert got2 == input_template, (
        f"InputTemplate round-trip mismatch on independent re-describe:\nsent={input_template!r}\ngot={got2!r}"
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
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
