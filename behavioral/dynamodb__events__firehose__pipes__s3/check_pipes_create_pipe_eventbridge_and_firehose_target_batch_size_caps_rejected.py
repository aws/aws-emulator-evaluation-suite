"""pipes-create-pipe-eventbridge-and-firehose-target-batch-size-caps-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-create-pipe-eventbridge-and-firehose-target-batch-size-caps-rejected"

GROUP = "rejection"

SERVICES = ["dynamodb", "events", "firehose", "pipes", "s3"]


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """CreatePipe refuses a DynamoDB-stream-sourced BatchSize above a target's documented cap
    (10 for an EventBridge event bus target, 500 for a Firehose delivery stream target) with
    ValidationException and creates nothing, while the cap value itself is accepted.
    """
    ddb = ctx.client("dynamodb")

    table = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    stream_arn = _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t.get("TableStatus") == "ACTIVE" and t.get("LatestStreamArn"),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"table {table} ACTIVE with a stream",
    )["LatestStreamArn"]

    default_bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/default"

    bucket = _create_bucket(ctx)
    firehose_role = _create_role(
        ctx,
        "firehose.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )
    firehose_arn = _create_delivery_stream(ctx, bucket=bucket, role_arn=firehose_role["arn"])

    role = _create_role(
        ctx,
        "pipes.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:DescribeStream",
                        "dynamodb:GetRecords",
                        "dynamodb:GetShardIterator",
                        "dynamodb:ListStreams",
                    ],
                    "Resource": stream_arn,
                },
                {"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": default_bus_arn},
                {"Effect": "Allow", "Action": ["firehose:PutRecordBatch"], "Resource": firehose_arn},
            ],
        },
    )

    # --- EventBridge event bus target: documented cap is 10. ---
    # The cap value runs first: it is the positive control, and its retry absorbs IAM propagation.
    accepted_bus = _create_pipe(
        ctx,
        source=stream_arn,
        target=default_bus_arn,
        role_arn=role["arn"],
        desired_state="STOPPED",
        wait_for="STOPPED",
        SourceParameters={
            "DynamoDBStreamParameters": {"StartingPosition": "LATEST", "BatchSize": 10}
        },
    )
    described = ctx.client("pipes").describe_pipe(Name=accepted_bus)
    assert (
        described["SourceParameters"]["DynamoDBStreamParameters"]["BatchSize"] == 10
    ), (
        f"the EventBridge event-bus control leg must accept and echo BatchSize=10, got "
        f"{described['SourceParameters']!r}"
    )

    rejected_bus = _xname(ctx, "pipe")
    code, message = _rejected_code(
        ctx,
        Name=rejected_bus,
        RoleArn=role["arn"],
        Source=stream_arn,
        SourceParameters={
            "DynamoDBStreamParameters": {"StartingPosition": "LATEST", "BatchSize": 11}
        },
        Target=default_bus_arn,
        DesiredState="STOPPED",
    )
    assert code == "ValidationException", (
        f"BatchSize=11 into an EventBridge event bus target must be refused with "
        f"ValidationException, got {code!r} ({message!r})"
    )
    assert message == (
        '{"ValidationErrorFields":[{"Name":"BatchSize","Message":"The configured batch size 11 '
        'is greater than the max supported batch size 10 for target events."}]}'
    ), f"unexpected refusal message for the event-bus batch-size cap: {message!r}"
    assert rejected_bus not in _pipe_names(ctx, rejected_bus), (
        f"the refused pipe {rejected_bus!r} must not appear in list_pipes"
    )

    # --- Firehose delivery stream target: documented cap is 500. ---
    accepted_fh = _create_pipe(
        ctx,
        source=stream_arn,
        target=firehose_arn,
        role_arn=role["arn"],
        desired_state="STOPPED",
        wait_for="STOPPED",
        SourceParameters={
            "DynamoDBStreamParameters": {
                "StartingPosition": "LATEST", "BatchSize": 500, "MaximumBatchingWindowInSeconds": 1
            }
        },
    )
    described = ctx.client("pipes").describe_pipe(Name=accepted_fh)
    assert (
        described["SourceParameters"]["DynamoDBStreamParameters"]["BatchSize"] == 500
    ), (
        f"the Firehose control leg must accept and echo BatchSize=500, got "
        f"{described['SourceParameters']!r}"
    )

    rejected_fh = _xname(ctx, "pipe")
    code, message = _rejected_code(
        ctx,
        Name=rejected_fh,
        RoleArn=role["arn"],
        Source=stream_arn,
        SourceParameters={
            "DynamoDBStreamParameters": {
                "StartingPosition": "LATEST", "BatchSize": 501, "MaximumBatchingWindowInSeconds": 1
            }
        },
        Target=firehose_arn,
        DesiredState="STOPPED",
    )
    assert code == "ValidationException", (
        f"BatchSize=501 into a Firehose delivery-stream target must be refused with "
        f"ValidationException, got {code!r} ({message!r})"
    )
    assert message == (
        '{"ValidationErrorFields":[{"Name":"BatchSize","Message":"The configured batch size 501 '
        'is greater than the max supported batch size 500 for target firehose."}]}'
    ), f"unexpected refusal message for the Firehose batch-size cap: {message!r}"
    assert rejected_fh not in _pipe_names(ctx, rejected_fh), (
        f"the refused pipe {rejected_fh!r} must not appear in list_pipes"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=1.0,
                description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it's gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_bucket(ctx) -> str:
    """Create a private S3 bucket (registers empty-then-delete teardown). Returns its name."""
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return name


def _delete_bucket(ctx, name: str) -> None:
    """Empty then delete an S3 bucket; not-found on either call means it's already gone."""
    s3 = ctx.client("s3")
    try:
        token = None
        while True:
            kwargs = {"Bucket": name}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if objects:
                s3.delete_objects(Bucket=name, Delete={"Objects": objects})
            token = resp.get("NextContinuationToken")
            if not token:
                break
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream(ctx, *, bucket: str, role_arn: str) -> str:
    """Create a DirectPut Firehose delivery stream writing to `bucket`; return its ARN."""
    firehose = ctx.client("firehose")
    name = _xname(ctx, "fh")
    last_err = None
    for _ in range(8):
        try:
            resp = firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 300},
                },
                Tags=_xsvc_tags_kv(),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and (
                "unable to assume role" in str(exc) or "not authorized" in str(exc)
            ):
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create delivery stream {name}: {last_err}")
    arn = resp["DeliveryStreamARN"]
    ctx.on_cleanup(lambda: _delete_delivery_stream_and_wait(ctx, name))
    _poll_until(
        ctx,
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"delivery stream {name} ACTIVE",
    )
    return arn


def _delete_delivery_stream_and_wait(ctx, name: str, timeout_s: float = 180.0) -> None:
    """DeleteDeliveryStream is asynchronous; wait until DescribeDeliveryStream reports it gone."""
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(3)
    raise TimeoutError(f"delivery stream {name} still exists {timeout_s:.0f}s after delete")


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for; return the pipe name.

    Retries only the assume-role errors of a freshly created role (IAM propagation), never a
    ValidationException, so a permanent rejection is not turned into a timeout.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(_teardown(lambda: ctx.client("pipes").delete_pipe(Name=name),
                             "NotFoundException"))
    _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


def _rejected_code(ctx, **kwargs) -> tuple[str, str]:
    """Call create_pipe expecting a rejection; return the AWS error (code, message).

    An accepted call raises (after registering teardown) instead of reading as a code mismatch.
    """
    pipes = ctx.client("pipes")
    name = kwargs.pop("Name")
    try:
        resp = pipes.create_pipe(Name=name, Tags=_xsvc_resource_tags(), **kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(_teardown(lambda: ctx.client("pipes").delete_pipe(Name=name),
                             "NotFoundException"))
    raise AssertionError(
        f"create_pipe({name!r}) was ACCEPTED where real AWS rejects it; response {resp!r}"
    )


def _pipe_names(ctx, name_prefix: str) -> set[str]:
    """Every pipe name under a prefix, fully paginated."""
    pipes = ctx.client("pipes")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NamePrefix": name_prefix}
        if token:
            kwargs["NextToken"] = token
        resp = pipes.list_pipes(**kwargs)
        names.update(p["Name"] for p in resp.get("Pipes", []))
        token = resp.get("NextToken")
        if not token:
            return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
