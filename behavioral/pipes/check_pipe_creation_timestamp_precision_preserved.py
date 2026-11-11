"""pipe-creation-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-creation-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["pipes"]

_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-ts"}
_TAG_LIST = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePipe returns the same timezone-aware CreationTime, sub-second precision included,
    on repeated reads; LastModifiedTime is stable and never precedes CreationTime."""
    pipes = ctx.client("pipes")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)
    role_arn = _create_pipe_role(ctx, [{"Effect": "Allow", "Action": "sqs:*", "Resource": [src_arn, tgt_arn]}])

    name = ctx.unique_name("sim2real-pipes-ts-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=name,
        RoleArn=role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags=_RES_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=name)))
    _wait_pipe_current_state(ctx, pipes, name, {"STOPPED"})

    d1 = pipes.describe_pipe(Name=name)
    # Fixed real-time hold (not a wait-for-condition): forces each read past a full
    # wall-clock second boundary, so a target that re-derives/rounds the timestamp
    # per call cannot coincidentally land on the same value by sampling too fast.
    _hold_seconds(3)
    d2 = pipes.describe_pipe(Name=name)
    _hold_seconds(3)
    d3 = pipes.describe_pipe(Name=name)

    assert d1["CreationTime"].tzinfo is not None, "CreationTime must be a timezone-aware timestamp"
    assert d1["CreationTime"] == d2["CreationTime"] == d3["CreationTime"], (
        "CreationTime must be stable across repeated DescribePipe reads, not re-rounded each time"
    )
    assert d1["CreationTime"].microsecond == d2["CreationTime"].microsecond == d3["CreationTime"].microsecond, (
        "sub-second precision of CreationTime must be preserved identically across reads"
    )
    # LastModifiedTime can only move forward from CreationTime as the pipe transitions
    # through its creation states (CREATING -> STOPPED); it must never precede it.
    assert d1["LastModifiedTime"] >= d1["CreationTime"], (
        f"LastModifiedTime ({d1['LastModifiedTime']}) must never precede CreationTime "
        f"({d1['CreationTime']})"
    )
    assert d1["LastModifiedTime"] == d2["LastModifiedTime"] == d3["LastModifiedTime"], (
        "LastModifiedTime must also be stable across repeated reads once no further "
        "transition is happening"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _safe_cleanup(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "NoSuchEntity",
            "NotFoundException",
            "QueueDoesNotExist",
        ):
            raise


def _hold_seconds(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(min(1.0, deadline - time.monotonic()))


def _create_sqs_queue(ctx, *, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipes-q-")
    attrs = {}
    if fifo:
        name = f"{name}.fifo"
        attrs["FifoQueue"] = "true"
        attrs["ContentBasedDeduplication"] = "true"
    if extra_attrs:
        attrs.update(extra_attrs)
    kwargs = {"QueueName": name, "tags": _RES_TAGS}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pipes.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG_LIST
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = ctx.unique_name("sim2real-pipes-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _create_pipe_with_retry(ctx, pipes, *, timeout_s=90, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _wait_pipe_current_state(ctx, pipes, name, states, timeout_s=150, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)["CurrentState"]
        if last in states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {states}, last state was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
