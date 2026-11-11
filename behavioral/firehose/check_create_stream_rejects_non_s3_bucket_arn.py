"""create-stream-rejects-non-s3-bucket-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-rejects-non-s3-bucket-arn"
GROUP = 'overly-permissive'
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
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result); return the result or fail at the deadline."""
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

    Firehose may have written into the bucket, and a non-empty bucket cannot be deleted.
    """
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
    """Create the S3 delivery bucket with a teardown that empties, deletes and confirms it gone."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-dst-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]},
    )

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
    """A real IAM role Firehose can assume; Firehose validates the role at CreateDeliveryStream."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParity firehose behavioral check role",
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
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

    DeleteDeliveryStream returns while still DELETING and is refused while CREATING.
    """
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
    """CreateDeliveryStream with teardown registered at creation, retrying while a role propagates.

    Firehose rejects a not-yet-assumable role with InvalidArgumentException.
    """
    fh = ctx.client("firehose")
    kwargs.setdefault("Tags", [{"Key": "purpose", "Value": "behavioral-check"}])
    deadline = time.monotonic() + 150
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

    Bucket and role come first so LIFO cleanup deletes stream, then role, then bucket.
    """
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
    """CreateDeliveryStream refuses a non-S3 ARN, a bare bucket name and an S3 ARN with '/' in the
    bucket name, each with the exact ValidationException naming bucketARN's regex and creating
    nothing, while the real S3 bucket ARN is accepted and echoed back.
    """
    fh = ctx.client("firehose")
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    account = _account_id(ctx)

    def _create(bucket_arn, name):
        return fh.create_delivery_stream(
            DeliveryStreamName=name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            },
        )

    # BucketARN has only a length constraint in the Smithy model; the regex is enforced server-side.
    # All legs share one code, so the member path and regex attribute the refusal to BucketARN.
    expected = (
        "1 validation error detected: Value at 'extendedS3DestinationConfiguration.bucketARN' failed to satisfy constraint: Member must satisfy regular expression pattern: " + r"arn:.*:s3:::[\w\.\-]{1,255}"
    )

    legs = [
        # A well-formed ARN for the wrong service.
        (
            "a non-S3 ARN",
            "sim2real-behav-fh-sqsarn-",
            f"arn:aws:sqs:{ctx.region}:{account}:{bucket}",
        ),
        # A bare bucket name instead of an ARN.
        ("a bare bucket name", "sim2real-behav-fh-barename-", bucket),
        # A correct arn: prefix with a bucket name the regex character class forbids.
        (
            "an S3 ARN whose bucket name contains '/'",
            "sim2real-behav-fh-slashname-",
            f"arn:aws:s3:::{bucket}/with/slash",
        ),
    ]
    for description, prefix, bad_arn in legs:
        name = ctx.unique_name(prefix)
        code, msg = _err(lambda a=bad_arn, n=name: _create(a, n))
        assert code == "ValidationException", (
            f"{description} as BucketARN must be refused by the server-side generic "
            f"request validator with ValidationException -- NOT Firehose's own "
            f"InvalidArgumentException, which this operation reserves for semantic "
            f"faults (measured on real AWS); got {code!r}: {msg!r}"
        )
        assert msg == expected, (
            f"{description}: expected message {expected!r}, got {msg!r}"
        )
        assert _status(ctx, name) is None, (
            f"the create refused for {description} must not have created {name}"
        )

    # Control: the same request with the real S3 ARN is accepted and echoes it back.
    n3 = ctx.unique_name("sim2real-behav-fh-goodbucket-")
    _create_stream(
        ctx, n3, ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket)
    )
    _wait_active(ctx, n3)
    ext = _describe(ctx, n3)["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert ext["BucketARN"] == _bucket_arn(bucket), ext["BucketARN"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
