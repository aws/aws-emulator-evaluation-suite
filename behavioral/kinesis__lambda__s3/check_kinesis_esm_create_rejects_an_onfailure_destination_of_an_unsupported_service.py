"""kinesis-esm-create-rejects-an-onfailure-destination-of-an-unsupported-service."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-create-rejects-an-onfailure-destination-of-an-unsupported-service"
GROUP = "event-source-mapping"
SERVICES = ["kinesis", "lambda", "s3"]


@tags("axis:rejection", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping on a Kinesis source refuses an OnFailure destination ARN naming a
    service outside {SQS, SNS, S3}, with no mapping left behind, while the identical call pointed
    at an S3 bucket is accepted and reaches Enabled.
    """
    lam = ctx.client("lambda")

    stream = _create_stream(ctx)
    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role_arn = _lambda_role(ctx, [
        {"Effect": "Allow",
         "Action": ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                    "kinesis:DescribeStreamSummary", "kinesis:ListShards"],
         "Resource": stream["arn"]},
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:ListBucket"],
         "Resource": [bucket_arn, f"{bucket_arn}/*"]},
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents",
                                       "logs:CreateLogGroup"], "Resource": "*"},
    ])
    name = _function(ctx, source="def handler(event, context):\n    return {'ok': True}\n",
                     role_arn=role_arn)

    # A DynamoDB table ARN is a well-formed ARN, but DynamoDB is not one of the service types
    # Lambda accepts as an ESM OnFailure destination; no table needs to exist behind it.
    unsupported = (f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/"
                   f"{ctx.unique_name('sim2real-xsvc-notdest-')}")
    code, message = _error(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=stream["arn"], FunctionName=name, BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            DestinationConfig={"OnFailure": {"Destination": unsupported}},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"an OnFailure destination naming a DynamoDB table returned {code!r}, expected "
        f"InvalidParameterValueException"
    )
    expected_message = "The service specified by the TargetArn isn't supported as a destination."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # the effect is absent: no mapping exists on the function at all
    assert _mappings_for(ctx, name) == [], (
        f"the refused create left mappings on {name!r}: {_mappings_for(ctx, name)!r}"
    )

    # positive control: the same call naming the S3 bucket, which IS a supported destination type
    # for a Kinesis source, is accepted and reaches Enabled, pinning the refusal to the
    # destination's SERVICE rather than to anything else about this function or source.
    created = lam.create_event_source_mapping(
        EventSourceArn=stream["arn"], FunctionName=name, BatchSize=1,
        StartingPosition="TRIM_HORIZON",
        DestinationConfig={"OnFailure": {"Destination": bucket_arn}},
    )
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_event_source_mapping(UUID=created["UUID"]), "ResourceNotFoundException"
    ))
    enabled = _poll(
        ctx, lambda: lam.get_event_source_mapping(UUID=created["UUID"]),
        lambda m: m["State"] in ("Enabled", "Disabled"),
        timeout_s=180.0, description=f"mapping {created['UUID']} reached a terminal state",
    )
    assert enabled["State"] == "Enabled", (
        f"the control mapping reached {enabled['State']!r} "
        f"({enabled.get('StateTransitionReason')!r}); if it had also been refused the assertion "
        f"above would be about the function or source, not the destination's service type"
    )
    assert enabled["DestinationConfig"]["OnFailure"]["Destination"] == bucket_arn, (
        f"the control mapping's destination is {enabled['DestinationConfig']!r}, expected {bucket_arn!r}"
    )
    assert [m["UUID"] for m in _mappings_for(ctx, name)] == [created["UUID"]], (
        f"the function's mappings are {_mappings_for(ctx, name)!r}, expected only the control"
    )


def _create_stream(ctx) -> dict[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-kin-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(_teardown(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True),
        "ResourceNotFoundException",
    ))
    summary = _poll(
        ctx, lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120, interval_s=3.0, description=f"Kinesis stream {name} ACTIVE",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return {"name": name, "arn": summary["StreamARN"]}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-dest-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket,
                              Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    _teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket")()


def _mappings_for(ctx, function_name: str) -> list[dict]:
    """PAGINATED mappings for *function_name*."""
    found: list[dict] = []
    for page in ctx.client("lambda").get_paginator("list_event_source_mappings").paginate(
        FunctionName=function_name
    ):
        found.extend(page["EventSourceMappings"])
    return found


def _error(fn) -> tuple[str, str]:
    """The (code, message) fn() raises. Raises when the call SUCCEEDS, which is the strongest
    possible signal and must not read like a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError("the call SUCCEEDED; real AWS rejects it")


def _teardown(undo, *not_found: str):
    """Run undo(); only *not_found codes mean the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, predicate, *, timeout_s=300.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise TimeoutError at the capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _lambda_role(ctx, statements: list) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-fnrole-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]

    def _cleanup() -> None:
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
                  "NoSuchEntity")()
        _teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")()

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return arn


def _zipped(source: str) -> bytes:
    """The handler as a deployment package built in memory, not an S3 asset."""
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buffer.getvalue()


def _function(ctx, *, source: str, role_arn: str, **kwargs) -> str:
    """CreateFunction with the bounded retry a fresh IAM role needs, then polled out of Pending."""
    lam = ctx.client("lambda")
    name = kwargs.pop("FunctionName", None) or ctx.unique_name("sim2real-xsvc-fn-")
    ctx.on_cleanup(lambda: _drop_function(ctx, name))
    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zipped(source)}, Tags={"sim2real": CHECK}, **kwargs,
            )
            break
        except ClientError as exc:
            last = exc
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or "cannot be assumed" not in err["Message"]:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"CreateFunction still refused after {timeout_s:.0f}s of role propagation: {last}"
                ) from exc
            time.sleep(5)
    config = _poll(
        ctx, lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] != "Pending",
        timeout_s=300.0, description=f"function {name} left Pending",
    )
    assert config["State"] == "Active", (
        f"function {name} reached state {config['State']!r} ({config.get('StateReason')!r}), not Active"
    )
    return name


def _drop_function(ctx, name: str) -> None:
    """Delete the function AND the log group Lambda created for it, re-deleting over a bounded
    window since a buffered flush can recreate the group after the delete."""
    _teardown(lambda: ctx.client("lambda").delete_function(FunctionName=name),
              "ResourceNotFoundException")()
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{name}"
    for _ in range(4):
        _teardown(lambda: logs.delete_log_group(logGroupName=log_group), "ResourceNotFoundException")()
        time.sleep(2)
        if not _log_group_present(ctx, log_group):
            return
    raise AssertionError(f"{log_group} kept reappearing after four deletes")


def _log_group_present(ctx, log_group: str) -> bool:
    for page in ctx.client("logs").get_paginator("describe_log_groups").paginate(
        logGroupNamePrefix=log_group
    ):
        if any(g["logGroupName"] == log_group for g in page["logGroups"]):
            return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
