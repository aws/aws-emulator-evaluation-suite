"""kinesis-source-stream-rejects-put-record."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-source-stream-rejects-put-record"
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

# Includes the Kinesis read actions a KinesisStreamAsSource stream needs.
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
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result); return the result or raise on the deadline."""
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

    Firehose may have written into the bucket, and a non-empty bucket cannot be deleted."""
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
    """Create the S3 delivery bucket with a teardown that empties, deletes and polls it gone."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-dst-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
    """A real IAM role Firehose can assume; Firehose validates the role at creation time."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParity firehose behavioral check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    """Poll to a deletable state, delete, then poll until the stream is gone.

    Delete is refused while the stream is CREATING and returns while it is still DELETING."""
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
    """CreateDeliveryStream with teardown registered, retrying while a new IAM role propagates
    (Firehose rejects a not-yet-assumable role with InvalidArgumentException)."""
    fh = ctx.client("firehose")
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": CHECK}])
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

    Bucket and role are created first, so LIFO cleanup tears down stream, role, then bucket."""
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


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A KinesisStreamAsSource stream reports its Kinesis source on Describe and refuses PutRecord
    with InvalidArgumentException, while a DirectPut stream accepts the same call and delivers it.
    """
    fh = ctx.client("firehose")
    kinesis = ctx.client("kinesis")

    # Billable: one 1-shard provisioned Kinesis data stream for the duration of the check.
    ks_name = ctx.unique_name("sim2real-behav-fh-src-")
    kinesis.create_stream(StreamName=ks_name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"})
    kinesis.add_tags_to_stream(StreamName=ks_name, Tags={"sim2real": CHECK})

    def _teardown_kinesis():
        try:
            kinesis.delete_stream(StreamName=ks_name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

        def _gone():
            try:
                kinesis.describe_stream_summary(StreamName=ks_name)
                return False
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return True
                raise

        _poll(
            _gone,
            lambda gone: gone is True,
            timeout_s=180,
            interval_s=5,
            description=f"LEAK guard: kinesis stream {ks_name} disappearance",
        )

    ctx.on_cleanup(_teardown_kinesis)

    ks_arn = _poll(
        lambda: kinesis.describe_stream_summary(StreamName=ks_name)[
            "StreamDescriptionSummary"
        ],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=300,
        interval_s=5,
        description=f"kinesis stream {ks_name} ACTIVE",
    )["StreamARN"]

    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)

    sourced = ctx.unique_name("sim2real-behav-fh-kinsrc-")
    _create_stream(
        ctx,
        sourced,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={
            "KinesisStreamARN": ks_arn,
            "RoleARN": role_arn,
        },
        ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket),
    )
    _wait_active(ctx, sourced)

    desc = _describe(ctx, sourced)
    assert desc["DeliveryStreamType"] == "KinesisStreamAsSource", desc["DeliveryStreamType"]
    src = desc["Source"]["KinesisStreamSourceDescription"]
    assert src["KinesisStreamARN"] == ks_arn, src["KinesisStreamARN"]
    assert src["RoleARN"] == role_arn, src["RoleARN"]
    assert src.get("DeliveryStartTimestamp") is not None, (
        f"a Kinesis-sourced stream must report DeliveryStartTimestamp, got {src!r}"
    )

    # The producer API on a stream that has a Kinesis source.
    code, msg = _err(
        lambda: fh.put_record(DeliveryStreamName=sourced, Record={"Data": b"direct"})
    )
    assert code == "InvalidArgumentException", (
        "PutRecord against a KinesisStreamAsSource stream must be refused with "
        f"InvalidArgumentException, got {code!r}: {msg!r}"
    )
    expected_msg = "This operation is not permitted on KinesisStreamAsSource delivery stream type."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The refusal does not disturb the stream or its source binding.
    after = _describe(ctx, sourced)
    assert after["DeliveryStreamStatus"] == "ACTIVE", after["DeliveryStreamStatus"]
    assert (
        after["Source"]["KinesisStreamSourceDescription"]["KinesisStreamARN"] == ks_arn
    ), after["Source"]

    # Control: the identical PutRecord succeeds on a DirectPut stream with the same bucket and role.
    direct, _b, _r = _active_stream(
        ctx, "sim2real-behav-fh-directctl-", bucket=bucket, role_arn=role_arn
    )
    marker = ctx.unique_name("sim2real-behav-fh-rec-").encode()
    ok = fh.put_record(DeliveryStreamName=direct, Record={"Data": marker + b"\n"})
    assert ok.get("RecordId"), f"PutRecord on a DirectPut stream must mint a RecordId: {ok!r}"

    # The accepted record must actually arrive in the destination bucket.
    s3 = ctx.client("s3")
    landed = _poll(
        lambda: [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])],
        lambda keys: len(keys) > 0,
        timeout_s=240,
        interval_s=10,
        description=f"PutRecord delivered to destination bucket {bucket}",
    )
    body = s3.get_object(Bucket=bucket, Key=landed[0])["Body"].read()
    assert marker in body, (
        f"delivered object {landed[0]!r} must contain the accepted PutRecord's payload; "
        f"got {body[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
