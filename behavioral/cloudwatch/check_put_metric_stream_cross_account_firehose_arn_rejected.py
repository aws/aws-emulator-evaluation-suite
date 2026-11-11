"""put-metric-stream-cross-account-firehose-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-cross-account-firehose-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream with a FirehoseArn whose account segment does not match
    the caller's account is rejected with InvalidParameterValue -- a distinct
    precondition from the IncludeFilters/ExcludeFilters conflict case."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    prereqs = _create_metric_stream_prereqs(ctx)
    real_firehose_arn = prereqs["firehose_arn"]
    cw_role_arn = prereqs["cw_role_arn"]

    # --- Positive control: valid, same-account FirehoseArn succeeds. The IAM
    # role's trust policy propagates asynchronously, and PutMetricStream can
    # transiently reject a just-created role with InvalidParameterValue before
    # it does -- so this is a bounded retry, not a fixed sleep.
    good_name = ctx.unique_name("sim2real-mstream-good-")
    _put_metric_stream_with_retry(
        cw,
        Name=good_name,
        FirehoseArn=real_firehose_arn,
        RoleArn=cw_role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=good_name))
    desc = cw.get_metric_stream(Name=good_name)
    assert desc["FirehoseArn"] == real_firehose_arn, (
        f"expected the positive-control stream's FirehoseArn to be {real_firehose_arn!r}, got {desc['FirehoseArn']!r}"
    )

    # --- Negative: same call, but FirehoseArn's account segment is swapped for a
    # syntactically valid but mismatched account. Must be rejected up front.
    bogus_account = "111111111111" if account_id != "111111111111" else "222222222222"
    bogus_firehose_arn = real_firehose_arn.replace(f":{account_id}:", f":{bogus_account}:")
    assert bogus_firehose_arn != real_firehose_arn, (
        f"expected the account swap to change the ARN, both are {bogus_firehose_arn!r}"
    )

    bad_name = ctx.unique_name("sim2real-mstream-bad-")
    try:
        cw.put_metric_stream(
            Name=bad_name,
            FirehoseArn=bogus_firehose_arn,
            RoleArn=cw_role_arn,
            OutputFormat="json",
        )
    except ClientError as exc:
        err = exc.response["Error"]
    else:
        ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=bad_name))
        raise AssertionError("expected PutMetricStream to reject a cross-account FirehoseArn, but it succeeded")
    assert err["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {err!r}"
    expected = "FirehoseArn must be in the same account as the Metric Stream"
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Effect absent: the rejected stream must not have been created.
    try:
        cw.get_metric_stream(Name=bad_name)
    except ClientError as exc:
        not_found = exc.response["Error"]
    else:
        raise AssertionError(f"rejected PutMetricStream must not create {bad_name}, but GetMetricStream succeeded")
    assert not_found["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found!r}"
    expected = ""
    assert not_found.get("Message", "") == expected, f"expected {expected!r}, got {not_found.get('Message', '')!r}"


def _put_metric_stream_with_retry(cw, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs) -> None:
    """PutMetricStream can transiently reject a just-created role/trust-policy
    with InvalidParameterValue until IAM propagation completes; retry that
    specific code up to a deadline instead of guessing a fixed delay."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"put_metric_stream did not succeed within {timeout_s}s of IAM propagation: {last_exc}")


def _create_metric_stream_prereqs(ctx) -> dict:
    """Provision a real S3-backed Firehose delivery stream plus the two IAM
    roles needed for CloudWatch -> Firehose -> S3, all in the caller's own
    account, so PutMetricStream can be exercised end to end."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    region = ctx.region

    bucket = ctx.unique_name("sim2real-mstream-dst-").lower()
    if region == "us-east-1":
        # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    firehose_role_name = ctx.unique_name("sim2real-mstream-fh-role-")
    firehose_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    firehose_role = iam.create_role(
        RoleName=firehose_role_name,
        AssumeRolePolicyDocument=json.dumps(firehose_trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=firehose_role_name))
    firehose_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}],
    }
    iam.put_role_policy(
        RoleName=firehose_role_name, PolicyName="s3-write", PolicyDocument=json.dumps(firehose_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=firehose_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-mstream-fh-")
    firehose_arn = _create_delivery_stream_with_retry(
        ctx, firehose, stream_name, bucket, firehose_role["Arn"]
    )

    cw_role_name = ctx.unique_name("sim2real-mstream-cw-role-")
    cw_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    cw_role = iam.create_role(
        RoleName=cw_role_name,
        AssumeRolePolicyDocument=json.dumps(cw_trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    cw_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": firehose_arn}],
    }
    iam.put_role_policy(RoleName=cw_role_name, PolicyName="firehose-write", PolicyDocument=json.dumps(cw_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-write"))

    return {"firehose_arn": firehose_arn, "cw_role_arn": cw_role["Arn"], "bucket": bucket}


def _create_delivery_stream_with_retry(ctx, firehose, stream_name, bucket, role_arn, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                },
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("InvalidArgumentException", "AccessDeniedException"):
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create Firehose delivery stream: {last_exc}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    return _wait_delivery_stream_active(firehose, stream_name)


def _wait_delivery_stream_active(firehose, stream_name, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"Firehose delivery stream {stream_name} never became ACTIVE")


def _empty_and_delete_bucket(s3, bucket) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
