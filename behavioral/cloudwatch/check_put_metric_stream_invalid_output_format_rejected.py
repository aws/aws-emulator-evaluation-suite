"""put-metric-stream-invalid-output-format-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-invalid-output-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream rejects an OutputFormat outside {json, opentelemetry0.7, opentelemetry1.0}."""
    cw = ctx.client("cloudwatch")
    infra = _create_metric_stream_infra(ctx)
    name = ctx.unique_name("sim2real-mstream-")

    err = _error(
        lambda: cw.put_metric_stream(
            Name=name,
            FirehoseArn=infra["firehose_arn"],
            RoleArn=infra["role_arn"],
            OutputFormat="not-a-real-format",
        )
    )
    assert err["Code"] == "ValidationError", f"expected ValidationError, got {err!r}"
    expected = "1 validation error detected: Value 'not-a-real-format' at 'outputFormat' failed to satisfy constraint: Member must satisfy enum value set: [opentelemetry1.0, json, opentelemetry0.7]"
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # effect absent: the stream was never created
    not_found = _error(lambda: cw.get_metric_stream(Name=name))
    assert not_found["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found!r}"
    expected = ""
    assert not_found.get("Message", "") == expected, f"expected {expected!r}, got {not_found.get('Message', '')!r}"

    # positive control: the identical request but with a valid OutputFormat succeeds
    resp = _retry_until_success(
        lambda: cw.put_metric_stream(
            Name=name,
            FirehoseArn=infra["firehose_arn"],
            RoleArn=infra["role_arn"],
            OutputFormat="json",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))
    assert resp["Arn"], f"expected an Arn in the PutMetricStream response, got {resp!r}"
    created = cw.get_metric_stream(Name=name)
    assert created["OutputFormat"] == "json", f"got {created['OutputFormat']!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError rejection, but the call succeeded and returned {result!r}")


def _retry_until_success(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    """Retries fn() past IAM/role-trust eventual-consistency windows, surfacing the last error."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cwms-")
    if ctx.region == "us-east-1":
        # S3 quirk: CreateBucketConfiguration/LocationConstraint is rejected in us-east-1.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_firehose_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwms-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="firehose-s3-access", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_delivery_stream(ctx, bucket_name: str, firehose_role_arn: str) -> str:
    fh = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-cwms-fh-")

    def _create():
        fh.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": firehose_role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket_name}",
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    _retry_until_success(_create, timeout_s=90.0, interval_s=5.0)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True))

    deadline = time.monotonic() + 120.0
    arn = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        arn = desc["DeliveryStreamARN"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return arn
        time.sleep(3.0)
    raise AssertionError(f"delivery stream {stream_name} never became ACTIVE (last status seen: {arn})")


def _create_metric_stream_role(ctx, firehose_stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwms-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                "Resource": firehose_stream_arn,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="cw-metric-stream-firehose", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_metric_stream_infra(ctx) -> dict:
    bucket = _create_bucket(ctx)
    firehose_role_arn = _create_firehose_role(ctx, bucket)
    firehose_arn = _create_delivery_stream(ctx, bucket, firehose_role_arn)
    role_arn = _create_metric_stream_role(ctx, firehose_arn)
    return {"firehose_arn": firehose_arn, "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
