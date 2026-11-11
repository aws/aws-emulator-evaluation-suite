"""put-record-rejected-while-stream-creating."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-rejected-while-stream-creating"
GROUP = 'lifecycle'
SERVICES = ['firehose']

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# The role is a throwaway created and deleted per check, so the broad policy is harmless.
ACCESS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "logs:PutLogEvents",
                "kinesis:DescribeStream",
                "kinesis:GetShardIterator",
                "kinesis:GetRecords",
                "kinesis:ListShards",
            ],
            "Resource": "*",
        }
    ],
}


def _poll(probe, predicate, *, timeout_s, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result); return the result. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observed {last!r}"
            )
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _bucket_arn(bucket):
    return f"arn:aws:s3:::{bucket}"


def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]


def _status(ctx, name):
    """Current DeliveryStreamStatus, or None once the stream has actually vanished."""
    try:
        return _describe(ctx, name)["DeliveryStreamStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _bucket_exists(ctx, bucket):
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchBucket"):
            return False
        raise


def _empty_bucket(ctx, bucket):
    """Remove every object, version, delete-marker and in-flight multipart upload.
    Firehose may have written into this bucket, and a bucket that still holds an
    object cannot be deleted -- so this must run to completion before delete_bucket."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            batch = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
            ]
            if batch:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})
    except ClientError:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            batch = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if batch:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"]
            )


def _make_bucket(ctx):
    """Create the S3 delivery bucket; register a teardown that empties it, deletes it,
    and polls until it is gone. A leaked bucket holding Firehose output bills for
    storage indefinitely, so the teardown retries and raises on a deadline miss."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-dst-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _teardown():
        deadline = time.monotonic() + 180
        while True:
            try:
                _empty_bucket(ctx, bucket)
                s3.delete_bucket(Bucket=bucket)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("NoSuchBucket", "404"):
                    return
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"LEAK: bucket {bucket} not deleted within 180s (last error {code})"
                    )
                time.sleep(2)
        _poll(
            lambda: _bucket_exists(ctx, bucket),
            lambda exists: exists is False,
            timeout_s=60,
            interval_s=3,
            description=f"bucket {bucket} disappearance",
        )

    ctx.on_cleanup(_teardown)
    return bucket


def _delivery_role_arn(ctx):
    """A real IAM role Firehose can assume -- Firehose validates the role at
    CreateDeliveryStream time, so a fabricated ARN is not usable."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParity firehose behavioral check role",
    )
    iam.put_role_policy(
        RoleName=role,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role, PolicyName=pn)
            iam.delete_role(RoleName=role)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]


def _delete_stream_and_wait(ctx, name, *, timeout_s=420):
    """Poll to a deletable state, delete, then poll to actual disappearance.
    delete_delivery_stream returns while the stream is still DELETING, and it is
    refused while the stream is CREATING."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while True:
        state = _status(ctx, name)
        if state is None:
            return
        if state != "DELETING":
            try:
                fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"LEAK: delivery stream {name} still {state} after {timeout_s}s"
            )
        time.sleep(2)


def _create_stream(ctx, name, **kwargs):
    """CreateDeliveryStream with teardown registered AT CREATION TIME, retrying while
    a brand-new IAM role is still propagating (Firehose rejects an unassumable role
    with InvalidArgumentException on the first try) -- bounded poll, never a sleep."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _budget_s(ctx, 150.0)
    while True:
        try:
            resp = fh.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            propagating = err.get("Code") == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if propagating and _budget_spent(ctx):
                raise TimeoutError(f"CreateDeliveryStream {name} past IAM propagation: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, name))
    return resp


def _s3_dest(role_arn, bucket, **overrides):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
    }
    cfg.update(overrides)
    return cfg


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_active(ctx, name, *, timeout_s=420):
    return _poll(
        lambda: _status(ctx, name),
        lambda s: s == "ACTIVE",
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1,
        description=f"delivery stream {name} ACTIVE",
        ctx=ctx,
    )


def _cloudwatch_incoming_records_sum(ctx, delivery_stream_name, since_utc):
    """Sum of AWS/Firehose IncomingRecords for this stream since `since_utc`, or None
    if CloudWatch has no datapoints yet."""
    cw = ctx.client("cloudwatch")
    end = datetime.datetime.now(datetime.timezone.utc)
    resp = cw.get_metric_statistics(
        Namespace="AWS/Firehose",
        MetricName="IncomingRecords",
        Dimensions=[{"Name": "DeliveryStreamName", "Value": delivery_stream_name}],
        StartTime=since_utc,
        EndTime=end,
        Period=300,
        Statistics=["Sum"],
    )
    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None
    return sum(dp["Sum"] for dp in datapoints)


def _active_stream(ctx, prefix, *, bucket=None, role_arn=None, **dest_overrides):
    """An ACTIVE DirectPut -> ExtendedS3 stream plus the bucket and role it needs.
    Bucket and role are created (and their teardowns registered) BEFORE the stream,
    so the LIFO cleanup order is stream -> role -> bucket: reverse-dependency."""
    if bucket is None:
        bucket = _make_bucket(ctx)
    if role_arn is None:
        role_arn = _delivery_role_arn(ctx)
    name = ctx.unique_name(prefix)
    _create_stream(
        ctx,
        name,
        ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket, **dest_overrides),
    )
    _wait_active(ctx, name)
    return name, bucket, role_arn


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord against a delivery stream still CREATING fails with ResourceNotFoundException and
    is never ingested; the same PutRecord succeeds and is delivered to S3 once the stream is ACTIVE.

    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_PutRecord.html
    """
    fh = ctx.client("firehose")
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-fh-creating-put-")

    # Full valid setup: a well-formed stream, deliberately NOT waited to ACTIVE.
    _create_stream(
        ctx, name, ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket)
    )

    # Break exactly one thing: write to it before it is ready, as the first call after the
    # create so the stream's own CREATING window is as wide as possible at the write.
    reject_call_start_utc = datetime.datetime.now(datetime.timezone.utc)
    try:
        fh.put_record(DeliveryStreamName=name, Record={"Data": b"too-early"})
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, msg = err.get("Code"), err.get("Message") or ""
    else:
        raise AssertionError(
            "precondition: CreateDeliveryStream must be asynchronous and leave the stream "
            f"CREATING; the first PutRecord after it was accepted (stream now "
            f"{_status(ctx, name)!r}). A synchronously-ACTIVE create is itself a fidelity defect "
            "(see check_create_stream_initial_state_creating)."
        )
    before = _status(ctx, name)
    assert code == "ResourceNotFoundException", (
        f"PutRecord against a CREATING stream must be refused with "
        f"ResourceNotFoundException, got {code!r}: {msg!r}"
    )
    assert msg == f"Firehose {name} is not active in {ctx.account} account.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {msg!r}"
    )

    # Effect absent: the rejected write did not disturb the stream's own lifecycle.
    after = _status(ctx, name)
    assert after in ("CREATING", "ACTIVE"), (
        f"a refused PutRecord must not change the stream's lifecycle; status went "
        f"{before!r} -> {after!r}"
    )

    # CloudWatch IncomingRecords independently shows the refused write was never ingested.
    incoming_while_creating = _cloudwatch_incoming_records_sum(
        ctx, name, since_utc=reject_call_start_utc
    )
    assert incoming_while_creating in (0, None), (
        f"IncomingRecords for the CREATING-state stream was "
        f"{incoming_while_creating!r}, want 0 -- the refused write must never reach "
        f"the ingestion layer"
    )

    # Control: the identical call succeeds once the stream is ACTIVE, proving the
    # refusal was about the CREATING state and not about the request.
    _wait_active(ctx, name)
    ok = fh.put_record(DeliveryStreamName=name, Record={"Data": b"too-early"})
    assert ok.get("RecordId"), f"PutRecord on an ACTIVE stream must mint a RecordId: {ok!r}"

    # A RecordId does not prove delivery; poll S3 until buffering flushes the record.
    s3 = ctx.client("s3")
    delivered = _poll(
        lambda: s3.list_objects_v2(Bucket=bucket).get("Contents", []),
        lambda objs: bool(objs),
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=1.0,
        description=f"record delivered to s3://{bucket}",
        ctx=ctx,
    )
    body = s3.get_object(Bucket=bucket, Key=delivered[0]["Key"])["Body"].read()
    assert b"too-early" in body, (
        f"S3 object delivered from the ACTIVE-state PutRecord did not contain the "
        f"written record bytes: {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
