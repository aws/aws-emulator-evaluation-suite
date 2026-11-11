"""put-record-nonexistent-stream-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-nonexistent-stream-not-found"
GROUP = 'error-semantics'
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


def _active_stream(ctx, prefix):
    """An ACTIVE DirectPut -> ExtendedS3 stream plus the bucket and role it needs.
    Bucket and role are created (and their teardowns registered) BEFORE the stream,
    so the LIFO cleanup order is stream -> role -> bucket: reverse-dependency."""
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    name = ctx.unique_name(prefix)
    _create_stream(ctx, name, ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket))
    _wait_active(ctx, name)
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord to a nonexistent stream raises ResourceNotFoundException instead of accepting the
    record; a positive control first proves PutRecord to a real ACTIVE stream returns a RecordId."""
    fh = ctx.client("firehose")
    live = _active_stream(ctx, "sim2real-behav-fh-nostream-ctrl-")
    ctrl = fh.put_record(DeliveryStreamName=live, Record={"Data": b"positive-control"})
    assert ctrl.get("RecordId"), f"positive control PutRecord must return a RecordId, got {ctrl!r}"

    absent = ctx.unique_name("sim2real-behav-fh-nostream-")
    code, message = _err(lambda: fh.put_record(DeliveryStreamName=absent, Record={"Data": b"x"}))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Firehose not found under account {ctx.account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
