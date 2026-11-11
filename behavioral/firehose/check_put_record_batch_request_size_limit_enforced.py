"""put-record-batch-request-size-limit-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-request-size-limit-enforced"
GROUP = 'data-plane'
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
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result); return the result."""
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
    A bucket that still holds an object cannot be deleted."""
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
    DeleteDeliveryStream returns while DELETING and is refused while CREATING."""
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
    (Firehose rejects an unassumable role with InvalidArgumentException)."""
    fh = ctx.client("firehose")
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
    Bucket and role are created first so LIFO cleanup tears down stream, role, then bucket."""
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecordBatch refuses a request over the 4 MB aggregate limit as a whole, even when each
    record and the record count are within limits; a batch under the aggregate is fully accepted.

    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_PutRecordBatch.html
    """
    fh = ctx.client("firehose")
    name, _bucket, _role = _active_stream(ctx, "sim2real-behav-fh-batchsize-")

    each = 900_000  # under the 1,024,000-byte per-record cap, so only the aggregate bites
    under = [{"Data": bytes([65 + i]) * each} for i in range(4)]  # 3.6 MB
    over = [{"Data": bytes([65 + i]) * each} for i in range(5)]  # 4.5 MB

    ok = fh.put_record_batch(DeliveryStreamName=name, Records=under)
    assert ok["FailedPutCount"] == 0, (
        f"a 3.6 MB batch is under the 4 MB request limit and must fully succeed, got "
        f"FailedPutCount={ok['FailedPutCount']}"
    )
    assert len(ok["RequestResponses"]) == len(under), (
        f"RequestResponses must be positionally aligned with the request: "
        f"{len(ok['RequestResponses'])} entries for {len(under)} records"
    )
    for i, entry in enumerate(ok["RequestResponses"]):
        assert entry.get("RecordId"), f"accepted record {i} must carry a RecordId: {entry!r}"
        assert "ErrorCode" not in entry, f"accepted record {i} must carry no ErrorCode: {entry!r}"

    code, msg = _err(lambda: fh.put_record_batch(DeliveryStreamName=name, Records=over))
    assert code == "InvalidArgumentException", (
        "a 4.5 MB PutRecordBatch exceeds the 4 MB per-request limit and must be refused "
        f"as a whole request, got {code!r}: {msg!r}"
    )
    assert msg == "Records size exceeds 4 MB limit", f"unexpected refusal message {msg!r}"

    # The stream stays writable: the refusal was about the request, not the stream.
    still = fh.put_record_batch(DeliveryStreamName=name, Records=under)
    assert still["FailedPutCount"] == 0, (
        f"the refused oversized batch must not have wedged the stream, got "
        f"FailedPutCount={still['FailedPutCount']}"
    )
    assert len(still["RequestResponses"]) == len(under), still["RequestResponses"]
    minted = {e["RecordId"] for e in ok["RequestResponses"]} | {
        e["RecordId"] for e in still["RequestResponses"]
    }
    assert len(minted) == 2 * len(under), (
        f"every accepted record must mint a distinct RecordId, got {len(minted)} for "
        f"{2 * len(under)} accepted records"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
