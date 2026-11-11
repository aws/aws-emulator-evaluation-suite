"""put-metric-stream-conflicting-include-exclude-filters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-conflicting-include-exclude-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricStream with IncludeFilters and ExcludeFilters fails InvalidParameterCombination.

    The two are mutually exclusive; the same call without filters succeeds, and the rejected
    stream does not exist afterwards.
    """
    cw = ctx.client("cloudwatch")
    firehose_arn = _create_backing_firehose(ctx)
    role_arn = _create_metric_stream_role(ctx, firehose_arn)

    # --- Positive control: the identical wiring, filters omitted, succeeds. CloudWatch checks the
    # filter combination before resolving the ARNs, but the control needs a real firehose and role.
    control_name = ctx.unique_name("sim2realbehavconflictok").replace("-", "")[:60]
    cw.put_metric_stream(
        Name=control_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json"
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=control_name))
    control_desc = cw.get_metric_stream(Name=control_name)
    assert control_desc["FirehoseArn"] == firehose_arn, (
        f"positive control: expected the control stream's FirehoseArn to be {firehose_arn!r}, "
        f"got {control_desc.get('FirehoseArn')!r}"
    )

    # --- Negative: the identical call, but with both IncludeFilters and ExcludeFilters set.
    stream_name = ctx.unique_name("sim2realbehavconflict").replace("-", "")[:60]

    err = _error(
        lambda: cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": "AWS/EC2"}],
            ExcludeFilters=[{"Namespace": "AWS/EBS"}],
        )
    )
    assert err["Code"] == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for IncludeFilters+ExcludeFilters together, got {err!r}"
    )
    expected = "IncludeFilters and ExcludeFilters cannot both be present"
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # The stream must not have been created.
    not_found = _error(lambda: cw.get_metric_stream(Name=stream_name))
    assert not_found["Code"] == "ResourceNotFoundException", (
        f"a metric stream rejected for a conflicting filter combination must not exist, "
        f"got GetMetricStream error {not_found!r}"
    )
    expected = ""
    assert not_found.get("Message", "") == expected, f"expected {expected!r}, got {not_found.get('Message', '')!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict of the ClientError it raises. An unexpected
    SUCCESS raises, because an over-permissive target accepting input real AWS refuses is the
    strongest signal available and must not be reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED and returned {result!r}")


# ===== helpers =====

def _create_backing_firehose(ctx) -> str:
    """Create an S3 bucket + Firehose delivery stream that PutMetricStream can reference."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket_name = ctx.unique_name("sim2real-behav-mstream-")
    if ctx.region == "us-east-1":
        # us-east-1 is a genuine S3 CreateBucket quirk: it rejects a LocationConstraint.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _TAGS})
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    fh_role_name = ctx.unique_name("sim2real-behav-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    _retry_propagation(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role, "BucketARN": bucket_arn},
            Tags=_TAGS,
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "creating the backing firehose delivery stream",
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError("firehose delivery stream never became ACTIVE")
    return arn


def _create_metric_stream_role(ctx, firehose_arn: str) -> str:
    iam = ctx.client("iam")
    cw = ctx.client("cloudwatch")
    role_name = ctx.unique_name("sim2real-behav-msrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="firehose-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-put"))

    # IAM role propagation: retry a throwaway PutMetricStream/DeleteMetricStream round trip.
    def _probe_stream() -> None:
        probe_name = ctx.unique_name("sim2real-behav-msprobe-")
        cw.put_metric_stream(
            Name=probe_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json"
        )
        cw.delete_metric_stream(Name=probe_name)

    _retry_propagation(
        ctx,
        _probe_stream,
        ("InvalidParameterValueException", "AccessDeniedException"),
        "the metric stream role becoming usable",
    )
    return role_arn


def _retry_propagation(ctx, fn, codes, what: str, timeout_s: float = 60.0):
    """Call fn(), retrying every 2 s while it raises one of the IAM propagation *codes*."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} did not succeed within {timeout_s}s: {e}") from e
        time.sleep(2)


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
