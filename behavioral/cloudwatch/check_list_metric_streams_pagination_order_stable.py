"""list-metric-streams-pagination-order-stable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metric-streams-pagination-order-stable"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated paginated ListMetricStreams calls return the same relative order for
    an unchanged set of streams, even when an unrelated metric stream is created
    between listing passes."""
    cw = ctx.client("cloudwatch")

    bucket_arn = _create_s3_bucket(ctx)
    delivery_role_arn = _create_firehose_delivery_role(ctx, bucket_arn)
    firehose_arn = _create_firehose_stream(ctx, bucket_arn, delivery_role_arn)
    stream_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    names = [ctx.unique_name(f"sim2reals{i}") for i in range(5)]
    for name in names:
        _put_metric_stream_with_retry(ctx, name, firehose_arn, stream_role_arn)
        ctx.on_cleanup(lambda n=name: cw.delete_metric_stream(Name=n))

    baseline_order = [n for n in _list_all_metric_streams(cw, max_results=2) if n in names]
    assert len(baseline_order) == len(names), (
        f"not all created streams appeared in the first listing pass: {baseline_order}"
    )

    # Create an unrelated stream mid-listing to prove it doesn't reorder the existing ones.
    extra_name = ctx.unique_name("sim2realextra")
    _put_metric_stream_with_retry(ctx, extra_name, firehose_arn, stream_role_arn)
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=extra_name))

    second_order = [n for n in _list_all_metric_streams(cw, max_results=2) if n in names]
    assert second_order == baseline_order, (
        f"stream order changed after an unrelated stream was created: {baseline_order} -> {second_order}"
    )

    third_order = [n for n in _list_all_metric_streams(cw, max_results=3) if n in names]
    assert third_order == baseline_order, (
        f"stream order changed with a different page size: {baseline_order} -> {third_order}"
    )


# ===== helpers =====

def _create_s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-mstream-dst-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 itself;
        # this compares against that fixed API quirk, not an assumption about ctx.region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=name, Key=o["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return f"arn:aws:s3:::{name}"


def _create_firehose_delivery_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mstream-fhrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="s3-access"))
    return role["Arn"]


def _create_firehose_stream(ctx, bucket_arn: str, role_arn: str) -> str:
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-mstream-fh-")
    last_err = None
    for _ in range(15):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:  # role not yet visible to firehose
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else min(90.0, left))
    while True:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        if time.monotonic() >= deadline:
            raise AssertionError("Firehose delivery stream never became ACTIVE")
        time.sleep(2)


def _create_metric_stream_role(ctx, firehose_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mstream-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
            "Resource": firehose_arn,
        }],
    }
    iam.put_role_policy(RoleName=name, PolicyName="firehose-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="firehose-access"))
    return role["Arn"]


def _put_metric_stream_with_retry(ctx, name: str, firehose_arn: str, role_arn: str, attempts: int = 15) -> None:
    cw = ctx.client("cloudwatch")
    last_err = None
    for _ in range(attempts):
        try:
            cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return
        except ClientError as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(3)
    raise last_err


def _list_all_metric_streams(cw, max_results: int) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"MaxResults": max_results}
        if token:
            kwargs["NextToken"] = token
        resp = cw.list_metric_streams(**kwargs)
        names.extend(e["Name"] for e in resp.get("Entries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
