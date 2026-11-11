"""pipe-description-empty-normalized-to-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-description-empty-normalized-to-absent"
GROUP = "representation"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipe created with Description="" has no Description on DescribePipe, like one created
    without it; UpdatePipe round-trips a real description and Description="" clears it."""
    source_a_url, source_a_arn = _create_queue(ctx)
    target_a_url, target_a_arn = _create_queue(ctx)
    source_b_url, source_b_arn = _create_queue(ctx)
    target_b_url, target_b_arn = _create_queue(ctx)
    role_arn = _create_pipe_role(
        ctx, [source_a_arn, source_b_arn], [target_a_arn, target_b_arn]
    )

    name_empty = ctx.unique_name("sim2real-pipe-desc-empty-")
    name_absent = ctx.unique_name("sim2real-pipe-desc-absent-")

    _create_pipe(
        ctx,
        name_empty,
        source_arn=source_a_arn,
        target_arn=target_a_arn,
        role_arn=role_arn,
        desired_state="STOPPED",
        extra_props={"Description": ""},
    )
    _create_pipe(
        ctx,
        name_absent,
        source_arn=source_b_arn,
        target_arn=target_b_arn,
        role_arn=role_arn,
        desired_state="STOPPED",
    )
    _wait_pipe_state(ctx, name_empty, {"STOPPED"}, timeout_s=90.0)
    _wait_pipe_state(ctx, name_absent, {"STOPPED"}, timeout_s=90.0)

    pipes = ctx.client("pipes")
    desc_empty = pipes.describe_pipe(Name=name_empty)
    desc_absent = pipes.describe_pipe(Name=name_absent)

    # Empty-string Description is not a distinct representation from no value.
    assert "Description" not in desc_empty, f"expected Description=\"\" to normalize to absent, got {desc_empty.get('Description')!r}"
    assert "Description" not in desc_absent, f"expected Description absent, got {desc_absent.get('Description')!r}"

    new_description = "now it has a description"
    pipes.update_pipe(Name=name_absent, RoleArn=role_arn, Description=new_description)
    _wait_pipe_state(ctx, name_absent, {"STOPPED"}, timeout_s=90.0)
    desc_after_update = pipes.describe_pipe(Name=name_absent)
    assert desc_after_update.get("Description") == new_description, (
        f"expected {new_description!r}, got {desc_after_update.get('Description')!r}"
    )

    pipes.update_pipe(Name=name_absent, RoleArn=role_arn, Description="")
    _wait_pipe_state(ctx, name_absent, {"STOPPED"}, timeout_s=90.0)
    desc_after_clear = pipes.describe_pipe(Name=name_absent)
    assert "Description" not in desc_after_clear, (
        f"expected Description cleared to absent, got {desc_after_clear.get('Description')!r}"
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


_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipe"}
_RES_TAGS_LIST = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


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


def _create_pipe_role(ctx, source_arns, target_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipe-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_RES_TAGS_LIST
    )["Role"]
    policy_name = "pipe-access"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": list(source_arns),
                },
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": list(target_arns)},
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
