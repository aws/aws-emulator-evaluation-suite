"""firehose-s3-destination-mismatched-bucket-arn-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-s3-destination-mismatched-bucket-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Firehose delivery stream whose S3 destination ARN points at a bucket that does not
    exist never produces delivered objects (Firehose logs S3.NoSuchBucket and keeps retrying),
    while a sibling stream pointed at a real bucket, using the same role and records, succeeds."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    good_bucket, good_bucket_arn = _create_bucket(ctx)

    # Wildcard S3 permission so the rejection below can only be explained by the bucket not
    # existing, never by an access-policy gap.
    role_arn = _create_role(ctx, [_s3_write_statement("*")], "mis")

    bad_bucket_name = ctx.unique_name("sim2real-fh-missing-")
    bad_bucket_arn = f"arn:aws:s3:::{bad_bucket_name}"

    # Firehose validates that the destination bucket exists synchronously at
    # CreateDeliveryStream time — so a mismatched/nonexistent bucket ARN surfaces as an
    # immediate InvalidArgumentException. That rejection IS the effect-absent signal: the
    # stream is never created, so it can never deliver a record to a bucket that isn't there.
    bad_stream = ctx.unique_name("sim2real-fh-bad-")
    denial = _create_delivery_stream_expect_denied(
        ctx,
        firehose,
        bad_stream,
        role_arn,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bad_bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    denial_code = denial.response["Error"]["Code"]
    denial_message = denial.response["Error"].get("Message")
    assert denial_code == "InvalidArgumentException", f"expected InvalidArgumentException, got {denial_code!r}: {denial_message!r}"
    want = f"S3 Bucket {bad_bucket_name} does not exist."
    assert denial_message == want, f"expected {want!r}, got {denial_message!r}"

    # Independent read: the rejection left no partial stream behind in Firehose's own
    # bookkeeping, so there is nothing there that could ever have delivered to bad_bucket_arn.
    describe_code, describe_message = _error(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream))
    assert describe_code == "ResourceNotFoundException", f"expected no partial stream, got {describe_code!r}"
    want_describe = f"Firehose under account {ctx.account} not found."
    assert describe_message == want_describe, f"expected {want_describe!r}, got {describe_message!r}"

    good_stream = ctx.unique_name("sim2real-fh-good-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        good_stream,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": good_bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _wait_delivery_stream_active(firehose, good_stream)

    marker = ctx.unique_name("marker-")
    firehose.put_record(DeliveryStreamName=good_stream, Record={"Data": f"payload-{marker}".encode()})

    # (a) effect absent, proven directly: the destination bucket genuinely never existed, so
    # the rejected stream could never have delivered anything to it.
    # A HEAD response carries no body, so AWS sends no error message to assert; the status is the signal.
    head_code, _ = _error(lambda: s3.head_bucket(Bucket=bad_bucket_name))
    assert head_code == "404", f"expected HeadBucket 404 for a bucket that never existed, got {head_code!r}"

    # (b) positive control: the same record reaches the sibling stream's real bucket.
    good_objects = _poll_until(
        lambda: _list_objects(s3, good_bucket), lambda o: len(o) >= 1, timeout_s=240, interval_s=10
    )
    assert len(good_objects) >= 1


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup() -> None:
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": name}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _s3_write_statement(bucket_arn: str) -> dict[str, Any]:
    resource = "*" if bucket_arn == "*" else [bucket_arn, f"{bucket_arn}/*"]
    return {
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": resource,
    }


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name(f"sim2real-fh-role-{suffix}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_delivery_stream_with_retry(ctx, firehose, name: str, **kwargs: Any) -> None:
    deadline = time.monotonic() + 150
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))


def _create_delivery_stream_expect_denied(
    ctx, firehose, name: str, role_arn: str, timeout_s: float = 120.0, **kwargs: Any
) -> ClientError:
    """Attempt CreateDeliveryStream expecting it to be rejected because the S3 destination
    bucket does not exist. Firehose validates this synchronously, so the rejection itself
    (InvalidArgumentException) is the effect-absent signal — the stream is never created and
    therefore can never deliver a record downstream. If the call unexpectedly succeeds, the
    stream is torn down and the check fails loudly.

    A role created seconds ago is refused with the same code and an "unable to assume role"
    message while IAM propagates; that refusal is retried, because it says nothing about the
    missing bucket under test."""
    propagating = f"Firehose is unable to assume role {role_arn}. Please check the role provided."
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException":
                if exc.response["Error"].get("Message") == propagating:
                    last_exc = exc
                    time.sleep(5)
                    continue
                return exc
            last_exc = exc
            time.sleep(5)
            continue
        else:
            ctx.on_cleanup(
                lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            )
            raise AssertionError(
                f"expected CreateDeliveryStream({name}) to be rejected for a nonexistent "
                "destination bucket, but it succeeded"
            )
    if last_exc is not None:
        raise last_exc
    raise AssertionError(f"create_delivery_stream({name}) did not fail as expected within {timeout_s}s")



def _wait_delivery_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=timeout_s,
        interval_s=5,
    )
    if status != "ACTIVE":
        raise AssertionError(f"delivery stream {name} failed to activate: {status}")


def _list_objects(s3, bucket: str, prefix: str = "") -> list[dict[str, Any]]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
