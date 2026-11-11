"""list-metric-streams-pagination-order-stable-across-pages."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-metric-streams-pagination-order-stable-across-pages"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListMetricStreams (MaxResults=1, forcing many pages) twice in a row
    returns the streams in the exact same order both times."""
    cw = ctx.client("cloudwatch")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    firehose_arn = _create_firehose_stream(ctx, role_arn, bucket)
    ms_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    names = [ctx.unique_name(f"sim2real-cw-mstream-ord-{i}-") for i in range(2)]
    for name in names:
        _retry_until_ready(
            lambda n=name: cw.put_metric_stream(
                Name=n,
                FirehoseArn=firehose_arn,
                RoleArn=ms_role_arn,
                OutputFormat="json",
                Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
            )
        )
        ctx.on_cleanup(lambda n=name: cw.delete_metric_stream(Name=n))

    def _list_all():
        out = []
        token = None
        while True:
            kwargs = {"MaxResults": 1}
            if token:
                kwargs["NextToken"] = token
            resp = cw.list_metric_streams(**kwargs)
            out.extend(e["Name"] for e in resp.get("Entries", []))
            token = resp.get("NextToken")
            if not token:
                break
        return out

    first = _list_all()
    second = _list_all()
    assert first == second, f"pagination order changed between traversals: {first} vs {second}"
    assert set(names).issubset(set(first)), "created metric streams missing from listing"


def _retry_until_ready(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise last_err


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cw-mstream-")
    # S3 CreateBucket rejects LocationConstraint entirely for us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _delete_role_quiet(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_firehose_role(ctx, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:AbortMultipartUpload", "s3:GetObject"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_metric_stream_role(ctx, firehose_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-ms-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["firehose:PutRecord", "firehose:PutRecordBatch", "firehose:DescribeDeliveryStream"],
                "Resource": firehose_arn,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="firehose-access", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_firehose_stream(ctx, role_arn, bucket_name):
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-cw-fh-")

    def _create():
        fh.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket_name}",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
        )

    _retry_until_ready(_create, timeout_s=90)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))

    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(5)
    if arn is None:
        raise AssertionError("firehose delivery stream never became ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
