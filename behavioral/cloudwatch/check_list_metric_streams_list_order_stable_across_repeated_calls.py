"""list-metric-streams-list-order-stable-across-repeated-calls."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metric-streams-list-order-stable-across-repeated-calls"
GROUP = "ordering"
SERVICES = ["cloudwatch"]

_TAGS = [
    {"Key": "sim2real", "Value": "list-metric-streams-list-order-stable-across-repeated-calls"},
    {"Key": "sim2real:managed", "Value": "true"},
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams returns a stable relative order for a fixed set of metric
    streams across repeated calls when nothing about them has changed."""
    cw = ctx.client("cloudwatch")
    target = _provision_firehose_target(ctx)

    # Scope each stream to a namespace nothing ever publishes to, so the streams
    # (which start in the "running" state) never actually pull or deliver any of
    # the account's real metrics while this check is alive.
    unused_namespace = ctx.unique_name("sim2real-cw-mstream-unused-ns-")

    stream_names = [ctx.unique_name(f"sim2real-cw-mstream-{i}-") for i in range(3)]
    for name in stream_names:
        _put_metric_stream_with_retry(ctx, name, target, unused_namespace)
        ctx.on_cleanup(lambda n=name: cw.delete_metric_stream(Name=n))

    orderings = []
    for _ in range(3):
        entries = _list_all_metric_stream_names(ctx)
        ours = [n for n in entries if n in stream_names]
        assert len(ours) == 3, f"expected all 3 created streams to be listed, got {ours}"
        orderings.append(ours)
        time.sleep(3)

    assert orderings[0] == orderings[1] == orderings[2], (
        f"ListMetricStreams order was not stable across repeated calls: {orderings}"
    )


def _retry(fn, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _provision_firehose_target(ctx) -> dict:
    """Creates a real S3 bucket + Firehose delivery stream + two IAM roles so that
    PutMetricStream has a genuinely existing FirehoseArn/RoleArn to reference."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-cw-mstream-dst-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    fh_role_name = ctx.unique_name("sim2real-cw-fhrole-")
    fh_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    fh_role = iam.create_role(
        RoleName=fh_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust), Tags=_TAGS
    )["Role"]
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
                        "Action": [
                            "s3:PutObject",
                            "s3:GetBucketLocation",
                            "s3:ListBucket",
                        ],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-cw-fh-")

    def _create_stream():
        return firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": fh_role["Arn"],
                "BucketARN": bucket_arn,
            },
            Tags=_TAGS,
        )

    # IAM role propagation into Firehose can lag by tens of seconds.
    _retry(_create_stream, timeout_s=90.0, interval_s=5.0)
    ctx.on_cleanup(
        lambda: firehose.delete_delivery_stream(
            DeliveryStreamName=stream_name, AllowForceDelete=True
        )
    )

    def _describe():
        return firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]

    def _is_active(desc):
        return desc["DeliveryStreamStatus"] == "ACTIVE"

    active_desc = _poll_until(_describe, _is_active, timeout_s=120.0, interval_s=5.0)
    firehose_arn = active_desc["DeliveryStreamARN"]

    cw_role_name = ctx.unique_name("sim2real-cw-mrole-")
    cw_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    cw_role = iam.create_role(
        RoleName=cw_role_name, AssumeRolePolicyDocument=json.dumps(cw_trust), Tags=_TAGS
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-write",
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
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-write")
    )

    return {"firehose_arn": firehose_arn, "role_arn": cw_role["Arn"]}


def _put_metric_stream_with_retry(ctx, name: str, target: dict, namespace: str) -> None:
    cw = ctx.client("cloudwatch")

    def _put():
        return cw.put_metric_stream(
            Name=name,
            FirehoseArn=target["firehose_arn"],
            RoleArn=target["role_arn"],
            OutputFormat="json",
            IncludeFilters=[{"Namespace": namespace}],
            Tags=_TAGS,
        )

    # IAM role propagation into CloudWatch's metric-stream validation can also lag.
    _retry(_put, timeout_s=90.0, interval_s=5.0)


def _list_all_metric_stream_names(ctx) -> list:
    cw = ctx.client("cloudwatch")
    names = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cw.list_metric_streams(**kwargs)
        names.extend(e["Name"] for e in resp.get("Entries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return names


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
