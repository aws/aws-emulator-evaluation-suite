"""put-metric-stream-concurrent-modification-detected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "put-metric-stream-concurrent-modification-detected"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


def _error_code(exc) -> str:
    return exc.response["Error"]["Code"]


def _retry_until_ready(fn, retryable_codes, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if _error_code(exc) not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _create_role(ctx, name, trust_service, inline_policy):
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return role_arn


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing PutMetricStream updates on one name each succeed or fail with exactly
    ConcurrentModificationException, and the stream converges to one running configuration whose
    single IncludeFilter is a namespace that was actually written.
    """
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-behav-mstream-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    firehose_role_arn = _create_role(
        ctx,
        ctx.unique_name("sim2real-behav-fh-role-"),
        "firehose.amazonaws.com",
        {
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

    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    delivery_stream_arn = _retry_until_ready(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": firehose_role_arn, "BucketARN": bucket_arn},
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["DeliveryStreamARN"],
        retryable_codes={"InvalidArgumentException", "AccessDeniedException"},
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
        status = status["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            break
        time.sleep(5)
    else:
        raise AssertionError("firehose delivery stream never became ACTIVE")

    cw_role_arn = _create_role(
        ctx,
        ctx.unique_name("sim2real-behav-cw-role-"),
        "streams.metrics.cloudwatch.amazonaws.com",
        {
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

    metric_stream_name = ctx.unique_name("sim2real-behav-mstream-")

    def _put(include_filters):
        return cw.put_metric_stream(
            Name=metric_stream_name,
            FirehoseArn=delivery_stream_arn,
            RoleArn=cw_role_arn,
            OutputFormat="json",
            IncludeFilters=include_filters,
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )

    created_arn = _retry_until_ready(
        lambda: _put([{"Namespace": "AWS/EC2"}])["Arn"],
        retryable_codes={"InvalidParameterValueException", "AccessDeniedException"},
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=metric_stream_name))
    assert created_arn.endswith(metric_stream_name)

    namespaces = [f"AWS/Sim2RealBehav{i}" for i in range(10)]

    def _worker(ns):
        try:
            resp = _put([{"Namespace": ns}])
            return ("ok", ns, resp["Arn"])
        except ClientError as exc:
            return ("error", ns, _error_code(exc))

    with ThreadPoolExecutor(max_workers=len(namespaces)) as pool:
        outcomes = list(pool.map(_worker, namespaces))

    allowed_error_codes = {"ConcurrentModificationException"}
    successes = [o for o in outcomes if o[0] == "ok"]
    errors = [o for o in outcomes if o[0] == "error"]

    for _, ns, code in errors:
        assert code in allowed_error_codes, f"unexpected error code racing namespace {ns!r} under contention: {code}"
    assert successes, "expected at least one concurrent PutMetricStream call to succeed"
    for _, ns, arn in successes:
        assert arn == created_arn, f"successful concurrent update (namespace {ns!r}) returned a different Arn: {arn}"

    # The winner is the initial write or one successful racer, never a blend.
    candidate_namespaces = {"AWS/EC2"} | {ns for _, ns, _ in successes}
    final = cw.get_metric_stream(Name=metric_stream_name)
    assert final["Name"] == metric_stream_name
    assert final["State"] == "running"
    assert final["Arn"] == created_arn
    final_namespaces = {f["Namespace"] for f in final["IncludeFilters"]}
    assert len(final["IncludeFilters"]) == 1, (
        f"race left a merged/corrupted filter set: {final['IncludeFilters']!r}"
    )
    assert final_namespaces <= candidate_namespaces, (
        f"final IncludeFilters {final_namespaces!r} is not among the namespaces actually "
        f"raced {candidate_namespaces!r} -- the stream reflects a write nobody made"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
