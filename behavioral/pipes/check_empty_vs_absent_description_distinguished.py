"""empty-vs-absent-description-distinguished."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "empty-vs-absent-description-distinguished"
GROUP = "representation"
SERVICES = ["pipes"]

_TRANSITIONAL = {"CREATING", "UPDATING", "DELETING", "STARTING", "STOPPING"}
_FAILED = {
    "CREATE_FAILED",
    "UPDATE_FAILED",
    "START_FAILED",
    "STOP_FAILED",
    "DELETE_FAILED",
    "CREATE_ROLLBACK_FAILED",
    "DELETE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_FAILED",
}

_RES_TAGS = {"sim2real:managed": "true", "sim2real:check": "empty-vs-absent-description-distinguished"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePipe omits Description both when it was omitted and when it was set to "".

    A non-empty Description is preserved, a positive control against a target that never
    implements the field.
    """
    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-src-")
    _, target_arn = _create_queue(ctx, "sim2real-pipes-tgt-")
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    pipes = ctx.client("pipes")

    name_empty = ctx.unique_name("sim2real-pipes-emptydesc-")
    pipes.create_pipe(
        Name=name_empty,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        Description="",
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name_empty))
    _wait_pipe_stable(ctx, name_empty)

    name_absent = ctx.unique_name("sim2real-pipes-absentdesc-")
    pipes.create_pipe(
        Name=name_absent,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name_absent))
    _wait_pipe_stable(ctx, name_absent)

    name_present = ctx.unique_name("sim2real-pipes-realdesc-")
    real_description = "sim2real real description"
    pipes.create_pipe(
        Name=name_present,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        Description=real_description,
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=name_present))
    _wait_pipe_stable(ctx, name_present)

    described_empty = pipes.describe_pipe(Name=name_empty)
    described_absent = pipes.describe_pipe(Name=name_absent)
    described_present = pipes.describe_pipe(Name=name_present)

    assert "Description" not in described_empty, (
        f"explicit empty-string description should be normalized to absent (real AWS behavior), "
        f"got {described_empty.get('Description')!r}"
    )
    assert "Description" not in described_absent, (
        f"omitted description should be absent from DescribePipe output, "
        f"got {described_absent.get('Description')!r}"
    )
    # Positive control: a target that never implements Description at all would otherwise pass
    # the two assertions above for free. This is the assertion such a target cannot satisfy.
    assert described_present.get("Description") == real_description, (
        f"a real, non-empty description must round-trip verbatim, "
        f"expected {real_description!r}, got {described_present.get('Description')!r}"
    )




def _create_queue(ctx, prefix):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_RES_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "pipe-access"
    policy_doc = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_pipe_stable(ctx, name, timeout_s=90.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)
        state = last["CurrentState"]
        if state in _FAILED:
            raise AssertionError(f"pipe {name} entered failure state {state}: {last.get('StateReason')}")
        if state not in _TRANSITIONAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"pipe {name} did not stabilize within {timeout_s}s "
        f"(last state {last['CurrentState'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
