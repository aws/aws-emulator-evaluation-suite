"""put-metric-stream-concurrent-modification-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-concurrent-modification-converges"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutMetricStream updates of one existing stream fail only with
    ConcurrentModificationException, at least one succeeds, and the final configuration holds
    exactly one IncludeFilters namespace, that of a racer that reported success."""
    cw = ctx.client("cloudwatch")

    bucket, bucket_arn = _create_bucket(ctx)
    fh_role_name, fh_role_arn = _create_role(ctx, "firehose.amazonaws.com")
    _put_role_policy(
        ctx,
        fh_role_name,
        "s3-write",
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
    firehose_arn = _create_delivery_stream(ctx, fh_role_arn, bucket_arn)

    ms_role_name, ms_role_arn = _create_role(ctx, "streams.metrics.cloudwatch.amazonaws.com")
    _put_role_policy(
        ctx,
        ms_role_name,
        "firehose-write",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": firehose_arn,
                }
            ],
        },
    )

    name = ctx.unique_name("sim2real-mstream-")
    namespaces = ["AWS/EC2", "AWS/S3", "AWS/Lambda", "AWS/RDS", "AWS/SNS", "AWS/SQS", "AWS/ELB", "AWS/DynamoDB"]

    _put_metric_stream_with_retry(ctx, name, firehose_arn, ms_role_arn, namespaces[0])
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    def _racer(namespace: str) -> dict[str, Any]:
        try:
            resp = cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=ms_role_arn,
                OutputFormat="json",
                IncludeFilters=[{"Namespace": namespace}],
            )
            return {"namespace": namespace, "ok": True, "arn": resp.get("Arn"), "code": None}
        except ClientError as exc:
            return {"namespace": namespace, "ok": False, "arn": None, "code": exc.response["Error"]["Code"]}

    with ThreadPoolExecutor(max_workers=len(namespaces)) as pool:
        results = list(pool.map(_racer, namespaces))

    unexpected = [r for r in results if not r["ok"] and r["code"] != "ConcurrentModificationException"]
    assert not unexpected, f"racer(s) failed with an unexpected (non-Concurrent) error: {unexpected}"

    winners = [r["namespace"] for r in results if r["ok"]]
    assert winners, f"every concurrent PutMetricStream racer failed: {results}"

    final = cw.get_metric_stream(Name=name)
    final_filters = final.get("IncludeFilters") or []
    assert len(final_filters) == 1, f"expected exactly one IncludeFilters entry (unmerged write), got {final_filters}"
    final_namespace = final_filters[0]["Namespace"]
    assert final_namespace in namespaces, f"final IncludeFilters namespace {final_namespace!r} not among attempted writes"
    assert final_namespace in winners, (
        f"final state {final_namespace!r} does not correspond to any racer that reported success: {results}"
    )


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-cwmscc-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_role(ctx, trust_principal: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, resp["Role"]["Arn"]


def _put_role_policy(ctx, role_name: str, policy_name: str, policy_doc: dict[str, Any]) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_delivery_stream(ctx, role_arn: str, bucket_arn: str) -> str:
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-")

    deadline = time.monotonic() + 120.0
    last_err = None
    created = False
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            created = True
            break
        except ClientError as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))

    deadline = time.monotonic() + 120.0
    arn = None
    status = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError(f"firehose delivery stream never became ACTIVE, last status={status!r}")
    return arn


def _put_metric_stream_with_retry(ctx, name, firehose_arn, role_arn, namespace, timeout_s: float = 90.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                IncludeFilters=[{"Namespace": namespace}],
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"put_metric_stream never succeeded (IAM propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
