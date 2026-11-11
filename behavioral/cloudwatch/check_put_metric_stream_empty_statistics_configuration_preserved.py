"""put-metric-stream-empty-statistics-configuration-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-empty-statistics-configuration-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real", "Value": "cw-mstream-empty-stats"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty StatisticsConfigurations list is normalized the same as an omitted field on read-back."""
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-cw-mstream").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    fh_role_name = ctx.unique_name("sim2real-cw-fh-role-")
    fh_role_arn = _create_role(
        ctx,
        iam,
        fh_role_name,
        trust_service="firehose.amazonaws.com",
        policy_name="s3-write",
        policy_document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                }
            ],
        },
    )

    stream_name = ctx.unique_name("sim2real-cw-fh-")
    delivery_stream_arn = _create_delivery_stream(ctx, firehose, stream_name, fh_role_arn, bucket_arn)

    cw_role_name = ctx.unique_name("sim2real-cw-mstream-role-")
    cw_role_arn = _create_role(
        ctx,
        iam,
        cw_role_name,
        trust_service="streams.metrics.cloudwatch.amazonaws.com",
        policy_name="firehose-put",
        policy_document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": delivery_stream_arn,
                }
            ],
        },
    )

    metric_stream_name = ctx.unique_name("sim2real-cw-mstream-")
    _put_metric_stream_with_retry(
        cw,
        Name=metric_stream_name,
        FirehoseArn=delivery_stream_arn,
        RoleArn=cw_role_arn,
        OutputFormat="json",
        StatisticsConfigurations=[],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=metric_stream_name))

    omitted_stream_name = ctx.unique_name("sim2real-cw-mstream-omit-")
    _put_metric_stream_with_retry(
        cw,
        Name=omitted_stream_name,
        FirehoseArn=delivery_stream_arn,
        RoleArn=cw_role_arn,
        OutputFormat="json",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=omitted_stream_name))

    resp_explicit_empty = cw.get_metric_stream(Name=metric_stream_name)
    resp_omitted = cw.get_metric_stream(Name=omitted_stream_name)

    # Empirically, real CloudWatch normalizes an explicit empty StatisticsConfigurations
    # list the same way it treats an omitted field: the key is absent from GetMetricStream
    # in both cases. A fidelity bug would show up as *divergence* between the two --
    # e.g. an emulator that echoes back `[]` for the explicit case (a distinction real
    # AWS does not preserve) or that fabricates the key for the omitted case.
    assert "StatisticsConfigurations" not in resp_explicit_empty, (
        f"expected StatisticsConfigurations to be absent for an explicit empty list "
        f"(matching real AWS's normalization), got {resp_explicit_empty.get('StatisticsConfigurations')!r}"
    )
    assert "StatisticsConfigurations" not in resp_omitted, (
        f"expected StatisticsConfigurations to be absent when omitted, "
        f"got {resp_omitted.get('StatisticsConfigurations')!r}"
    )

    # The explicit-empty stream is proven live above; deleting it and re-reading (a
    # different operation again) proves the earlier GetMetricStream reads were not
    # merely tolerant of a stream that was never really there.
    cw.delete_metric_stream(Name=metric_stream_name)
    try:
        cw.get_metric_stream(Name=metric_stream_name)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after deleting {metric_stream_name}, got {err!r}"
        )
        expected = ""
        assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"
    else:
        raise AssertionError(
            f"expected GetMetricStream to fail for deleted stream {metric_stream_name}, but it succeeded"
        )


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for;
    # this is S3's own API quirk, not an assumption about which region the check runs in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})


def _create_role(ctx, iam, role_name: str, *, trust_service: str, policy_name: str, policy_document: dict) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )["Role"]
    # Registered in reverse-of-execution order so cleanup (LIFO) deletes the inline
    # policy before the role -- IAM refuses to delete a role with policies attached.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
    return role["Arn"]


def _create_delivery_stream(ctx, firehose, stream_name: str, role_arn: str, bucket_arn: str) -> str:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=_TAGS,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    deadline = time.monotonic() + 180.0
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream never became ACTIVE: {desc['DeliveryStreamStatus']}")
        time.sleep(5.0)


def _put_metric_stream_with_retry(cw, **kwargs) -> None:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            cw.put_metric_stream(**kwargs)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterValue", "InvalidParameterValueException") and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
