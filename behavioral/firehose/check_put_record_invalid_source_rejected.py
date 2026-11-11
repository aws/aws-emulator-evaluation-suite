"""put-record-invalid-source-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-record-invalid-source-rejected"
GROUP = "representation"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecord on a KinesisStreamAsSource stream fails with InvalidArgumentException and delivers
    nothing; a DirectPut sibling on the same wiring delivers to S3."""
    setup = _create_firehose_role_and_bucket_with_kinesis(ctx)
    fh = ctx.client("firehose")
    s3 = ctx.client("s3")

    # --- positive control: a DirectPut stream accepts PutRecord end-to-end ---
    control_name = ctx.unique_name("sim2real-fh-ctrl-")
    control_prefix = "control/"
    control_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "Prefix": control_prefix,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    _create_delivery_stream_with_retry(
        ctx, fh, control_name, control_config, "DirectPut", tag_value=CHECK
    )
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=control_name))
    _wait_active(ctx, fh, control_name)

    # --- the stream under test: KinesisStreamAsSource, which must reject PutRecord ---
    negative_name = ctx.unique_name("sim2real-fh-neg-")
    negative_prefix = "negative/"
    negative_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "Prefix": negative_prefix,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    _create_delivery_stream_with_retry(
        ctx,
        fh,
        negative_name,
        negative_config,
        "KinesisStreamAsSource",
        kinesis_source_arn=setup["kinesis_stream_arn"],
        role_arn=setup["role_arn"],
        tag_value=CHECK,
    )
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=negative_name))
    _wait_active(ctx, fh, negative_name)

    # InvalidSourceException is documented for CloudWatch Logs decompression, not this case.
    code, message = _error_code(
        lambda: fh.put_record(
            DeliveryStreamName=negative_name, Record={"Data": b"should-be-rejected\n"}
        )
    )
    assert code == "InvalidArgumentException", f"code={code!r}"
    assert message == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"unexpected refusal message {message!r}"
    )

    # The sibling's measured delivery time on identical wiring bounds the absence check below.
    marker = ctx.unique_name("sim2real-fh-rec-").encode()
    resp = fh.put_record(
        DeliveryStreamName=control_name, Record={"Data": marker + b"\n"}
    )
    assert resp.get("RecordId"), f"PutRecord on the DirectPut control must mint a RecordId: {resp!r}"
    control_objects = _poll_for_objects(
        ctx, setup["bucket"], prefix=control_prefix, min_count=1, timeout_s=240
    )
    assert control_objects, "control PutRecord never landed in S3"
    body = s3.get_object(Bucket=setup["bucket"], Key=control_objects[0]["Key"])["Body"].read()
    assert marker in body, (
        f"delivered object {control_objects[0]['Key']!r} must contain the accepted "
        f"record's payload; got {body[:200]!r}"
    )

    # No further sleep: delivery on identical wiring has already completed.
    leaked = _list_objects(ctx, setup["bucket"], prefix=negative_prefix)
    assert not leaked, f"rejected PutRecord still resulted in delivered S3 object(s): {leaked}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _role_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "firehose.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_firehose_role_and_bucket_with_kinesis(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    stream_name = ctx.unique_name("sim2real-fh-src-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _wait_kinesis_active(ctx, kinesis, stream_name)
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": CHECK})
    kinesis_stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)[
        "StreamDescriptionSummary"
    ]["StreamARN"]

    role_name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_role_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "kinesis:DescribeStream",
                        "kinesis:DescribeStreamSummary",
                        "kinesis:GetShardIterator",
                        "kinesis:GetRecords",
                        "kinesis:ListShards",
                    ],
                    "Resource": kinesis_stream_arn,
                },
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return {
        "bucket": bucket,
        "role_arn": role["Arn"],
        "kinesis_stream_arn": kinesis_stream_arn,
    }


def _wait_kinesis_active(ctx, kinesis, name: str, timeout_s: int = 120) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)[
            "StreamDescriptionSummary"
        ]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(5)
    raise AssertionError(f"kinesis stream {name} did not become ACTIVE within {timeout_s}s")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_delivery_stream_with_retry(
    ctx,
    fh,
    name: str,
    s3_config: dict,
    delivery_stream_type: str,
    kinesis_source_arn: str | None = None,
    role_arn: str | None = None,
    tag_value: str | None = None,
) -> None:
    from botocore.exceptions import ClientError

    kwargs = {
        "DeliveryStreamName": name,
        "DeliveryStreamType": delivery_stream_type,
        "ExtendedS3DestinationConfiguration": s3_config,
    }
    if delivery_stream_type == "KinesisStreamAsSource":
        kwargs["KinesisStreamSourceConfiguration"] = {
            "KinesisStreamARN": kinesis_source_arn,
            "RoleARN": role_arn,
        }
    if tag_value:
        kwargs["Tags"] = [{"Key": "sim2real", "Value": tag_value}]
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    raise last_err


def _wait_active(ctx, fh, name: str, timeout_s: int = 180) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("FAILED"):
            raise AssertionError(f"stream entered failed state: {status}")
        time.sleep(5)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _list_objects(ctx, bucket: str, prefix: str = "") -> list:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


def _poll_for_objects(
    ctx,
    bucket: str,
    prefix: str = "",
    min_count: int = 1,
    timeout_s: int = 240,
    interval_s: int = 10,
) -> list:
    deadline = time.monotonic() + timeout_s
    objs: list = []
    while time.monotonic() < deadline:
        objs = _list_objects(ctx, bucket, prefix=prefix)
        if len(objs) >= min_count:
            return objs
        time.sleep(interval_s)
    raise AssertionError(
        f"expected >= {min_count} objects under {prefix!r} in {bucket} within "
        f"{timeout_s}s, got {len(objs)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
