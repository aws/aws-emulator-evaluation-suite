"""update-destination-type-change-requires-full-config."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-destination-type-change-requires-full-config"
GROUP = 'update-destination'
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


def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected success
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result); return the result. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
                time.sleep(5)
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
    iam.tag_role(RoleName=role, Tags=[{"Key": "sim2real", "Value": CHECK}])

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
    """Poll to a deletable state, delete, then poll to ACTUAL disappearance.
    delete_delivery_stream returns while the stream is still DELETING, and it is
    refused outright while the stream is CREATING -- a fire-and-forget delete
    therefore silently leaks the stream."""
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
        time.sleep(5)


def _create_stream(ctx, name, **kwargs):
    """CreateDeliveryStream with teardown registered AT CREATION TIME, retrying while
    a brand-new IAM role is still propagating (Firehose rejects an unassumable role
    with InvalidArgumentException on the first try) -- bounded poll, never a sleep."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 150
    while True:
        try:
            resp = fh.create_delivery_stream(
                DeliveryStreamName=name,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
                **kwargs,
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            propagating = err.get("Code") == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, name))
    return resp


def _s3_dest(role_arn, bucket, **overrides):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }
    cfg.update(overrides)
    return cfg


def _wait_active(ctx, name, *, timeout_s=420):
    return _poll(
        lambda: _status(ctx, name),
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=5,
        description=f"delivery stream {name} ACTIVE",
    )


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination merges a same-type ExtendedS3 partial update but refuses a switch to
    HttpEndpoint with InvalidArgumentException, leaving destination, config and VersionId
    untouched."""
    fh = ctx.client("firehose")
    name, bucket, role_arn = _active_stream(
        ctx, "sim2real-behav-fh-desttype-", Prefix="events/data/"
    )
    desc = _describe(ctx, name)
    dest_id = desc["Destinations"][0]["DestinationId"]
    v1 = desc["VersionId"]

    # Control A -- same-type PARTIAL update: merge semantics, unspecified fields retained.
    fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=v1,
        DestinationId=dest_id,
        ExtendedS3DestinationUpdate={
            "BufferingHints": {"SizeInMBs": 2, "IntervalInSeconds": 90}
        },
    )
    merged = _poll(
        lambda: _describe(ctx, name),
        lambda d: d["VersionId"] != v1,
        timeout_s=180,
        interval_s=5,
        description="VersionId advanced after the same-type partial update",
    )
    v2 = merged["VersionId"]
    ext = merged["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert ext["BufferingHints"]["SizeInMBs"] == 2, ext["BufferingHints"]
    assert ext["Prefix"] == "events/data/", (
        f"a same-type partial update must MERGE: Prefix should survive, got {ext.get('Prefix')!r}"
    )
    assert ext["RoleARN"] == role_arn, (
        f"a same-type partial update must MERGE: RoleARN should survive, got {ext.get('RoleARN')!r}"
    )

    # Break exactly one thing: switch the destination TYPE while supplying only one field.
    err = _err(
        lambda: fh.update_destination(
            DeliveryStreamName=name,
            CurrentDeliveryStreamVersionId=v2,
            DestinationId=dest_id,
            HttpEndpointDestinationUpdate={
                "EndpointConfiguration": {
                    "Url": "https://firehose-sink.invalid/ingest",
                    "Name": "sim2real-behav-sink",
                }
            },
        )
    )
    assert err.get("Code") == "InvalidArgumentException", (
        "a destination-TYPE change with an incomplete configuration must be refused with "
        f"InvalidArgumentException, got {err!r}"
    )
    expected_msg = "Changing the destination type to or from HttpEndpoint is not supported at this time."
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Effect absent: destination type, configuration and version are all unchanged.
    after = _describe(ctx, name)
    dest = after["Destinations"][0]
    assert "HttpEndpointDestinationDescription" not in dest, (
        f"the refused type change must not have been applied: {sorted(dest)}"
    )
    assert "ExtendedS3DestinationDescription" in dest, sorted(dest)
    assert after["VersionId"] == v2, (
        f"a refused UpdateDestination must not advance VersionId: {v2!r} -> {after['VersionId']!r}"
    )
    ext_after = dest["ExtendedS3DestinationDescription"]
    assert ext_after["Prefix"] == "events/data/", ext_after.get("Prefix")
    assert ext_after["BufferingHints"]["SizeInMBs"] == 2, ext_after["BufferingHints"]
    assert ext_after["RoleARN"] == role_arn, ext_after.get("RoleARN")

    # Control B: the same-type path still works, so the stream was not wedged.
    fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=v2,
        DestinationId=dest_id,
        ExtendedS3DestinationUpdate={
            "BufferingHints": {"SizeInMBs": 3, "IntervalInSeconds": 90}
        },
    )
    final = _poll(
        lambda: _describe(ctx, name),
        lambda d: d["VersionId"] != v2,
        timeout_s=180,
        interval_s=5,
        description="VersionId advanced after the control update",
    )
    assert (
        final["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"][
            "SizeInMBs"
        ]
        == 3
    ), final["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
