"""put-record-empty-payload-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-empty-payload-blocked"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord accepts empty Data but rejects a malformed DeliveryStreamName with the exact
    ValidationException, before any not-found lookup; the bad name never appears in the list.
    """
    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _setup_destination(ctx)

    name = ctx.unique_name("sim2real-fh-putrec-")
    _create_stream_with_role_retry(
        firehose,
        DeliveryStreamName=name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, name))
    _wait_for_stream_active(firehose, name)

    # Firehose has no minimum Data size: an empty blob gets a normal RecordId.
    resp = firehose.put_record(DeliveryStreamName=name, Record={"Data": b""})
    assert resp["RecordId"], "expected a non-empty RecordId even for an empty-Data record"

    # Name-pattern validation runs before the existence lookup.
    bad_name = name + "!!invalid$$"
    code, message = _error_code(
        lambda: firehose.put_record(DeliveryStreamName=bad_name, Record={"Data": b"x"})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed DeliveryStreamName, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'deliveryStreamName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = firehose.list_delivery_streams(Limit=100).get("DeliveryStreamNames", [])
    assert bad_name not in names, (
        f"malformed name {bad_name!r} unexpectedly appears in list_delivery_streams: {names!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-fh-bkt-").lower().replace("_", "-")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _bucket_name(ctx)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return f"arn:aws:s3:::{name}"


def _create_trusted_role(ctx, trust_service: str = "firehose.amazonaws.com") -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


def _setup_destination(ctx):
    bucket_arn = _create_bucket(ctx)
    role_arn = _create_trusted_role(ctx, "firehose.amazonaws.com")
    return bucket_arn, role_arn


def _create_stream_with_role_retry(firehose, timeout_s: float = 45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "assume" in msg:
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_stream_active(firehose, name: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"stream {name} failed to create: {desc.get('FailureDescription')}")
        time.sleep(3)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
