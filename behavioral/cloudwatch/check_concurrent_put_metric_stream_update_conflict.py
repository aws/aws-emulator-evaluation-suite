"""concurrent-put-metric-stream-update-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-metric-stream-update-conflict"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing PutMetricStream updates on one stream fail only with ConcurrentModificationException,
    and the final IncludeFilters match exactly one racer that reported success."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-cw-mstream-").lower()
    # LocationConstraint must be omitted for us-east-1 -- the S3 API rejects it otherwise; this
    # is not a region pin, every other region takes the explicit constraint below.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _TAGS})
    ctx.on_cleanup(lambda: _force_delete_bucket(s3, bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    role_name = ctx.unique_name("sim2real-cw-mstream-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonKinesisFirehoseFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    stream_name = ctx.unique_name("sim2real-cw-mstream-")
    firehose_arn = _create_delivery_stream_with_retry(
        firehose, stream_name, role_arn, bucket_arn, _TAGS
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )

    metric_stream_name = ctx.unique_name("sim2real-cw-metricstream-")
    _put_metric_stream_with_retry(
        cw,
        Name=metric_stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "NS-initial"}],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=metric_stream_name))

    n = 8
    barrier = threading.Barrier(n)

    def racer(i: int) -> Optional[str]:
        barrier.wait()
        try:
            cw.put_metric_stream(
                Name=metric_stream_name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                IncludeFilters=[{"Namespace": f"NS-{i}"}],
            )
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(racer, range(n)))

    error_codes = {c for c in results if c is not None}
    assert error_codes <= {"ConcurrentModificationException"}, (
        f"concurrent PutMetricStream updates surfaced an unexpected error code: {error_codes}"
    )
    succeeded = {i for i, code in enumerate(results) if code is None}
    assert succeeded, (
        f"no concurrent PutMetricStream writer reported success under the race; codes={sorted(error_codes)}"
    )

    final = cw.get_metric_stream(Name=metric_stream_name)
    filters = final.get("IncludeFilters", [])
    assert len(filters) == 1, f"metric stream configuration corrupted by the race: {filters!r}"
    final_namespace = filters[0]["Namespace"]
    allowed = {f"NS-{i}" for i in succeeded}
    assert final_namespace in allowed, (
        f"final IncludeFilters namespace {final_namespace!r} does not correspond to any racer that "
        f"actually reported success ({sorted(succeeded)}); a writer whose call errored must never win"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _create_delivery_stream_with_retry(
    firehose: Any, stream_name: str, role_arn: str, bucket_arn: str, tags: list
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=tags,
            )
            return resp["DeliveryStreamARN"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidArgumentException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"could not create Firehose delivery stream after IAM propagation wait: {last_exc}")


def _put_metric_stream_with_retry(cw: Any, **kwargs: Any) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"could not create metric stream after IAM propagation wait: {last_exc}")


def _delete_role(iam: Any, role_name: str) -> None:
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonKinesisFirehoseFullAccess",
    ):
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _force_delete_bucket(s3: Any, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
