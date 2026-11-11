"""put-record-batch-invalid-source-kinesis-backed-stream."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-batch-invalid-source-kinesis-backed-stream"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecordBatch against a Kinesis-sourced delivery stream is refused wholesale with
    InvalidArgumentException, while the identical batch call against a DirectPut stream
    (positive control) succeeds with FailedPutCount == 0."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    _kinesis_name, kinesis_arn = _kinesis_stream(ctx)

    firehose = ctx.client("firehose")

    direct_name = ctx.unique_name("sim2real-fh-direct-")
    _create_delivery_stream_with_retry(
        ctx,
        DeliveryStreamName=direct_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=direct_name))

    kinesis_backed_name = ctx.unique_name("sim2real-fh-kdssrc-")
    _create_delivery_stream_with_retry(
        ctx,
        DeliveryStreamName=kinesis_backed_name,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": kinesis_arn, "RoleARN": role_arn},
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=kinesis_backed_name))

    _wait_stream_active(ctx, direct_name)
    kdesc = _wait_stream_active(ctx, kinesis_backed_name)
    assert (
        kdesc["Source"]["KinesisStreamSourceDescription"]["KinesisStreamARN"] == kinesis_arn
    )

    batch = [{"Data": b"rec-0"}, {"Data": b"rec-1"}]

    # Positive control: DirectPut stream accepts PutRecordBatch, no partial failures.
    ok = firehose.put_record_batch(DeliveryStreamName=direct_name, Records=batch)
    assert ok["FailedPutCount"] == 0
    assert len(ok["RequestResponses"]) == 2
    assert all(r["RecordId"] for r in ok["RequestResponses"])

    # Negative: the Kinesis-sourced stream must refuse the whole PutRecordBatch call. Firehose
    # rejects direct-put calls against a KinesisStreamAsSource delivery stream with
    # InvalidArgumentException (InvalidSourceException is reserved for a different scenario:
    # non-CloudWatch-Logs callers when CloudWatch Logs decompression is enabled).
    try:
        firehose.put_record_batch(DeliveryStreamName=kinesis_backed_name, Records=batch)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidArgumentException"
        msg = e.response["Error"].get("Message")
        expected_msg = "This operation is not permitted on KinesisStreamAsSource delivery stream type."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError(
            "expected InvalidArgumentException for PutRecordBatch on a Kinesis-sourced stream"
        )


def _iam_role_for_firehose(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*", "kinesis:*", "kms:*"], "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-fh-inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline"))
    return role_arn


def _create_delivery_stream_with_retry(ctx, attempts: int = 4, delay_s: float = 15.0, **kwargs) -> None:
    """CreateDeliveryStream can reject with InvalidArgumentException while IAM's own
    eventual consistency has not yet made the role assumable by Firehose; retry on that
    specific code rather than trusting a fixed sleep, so a slower-converging account is not
    scored as a fidelity mismatch."""
    firehose = ctx.client("firehose")
    last_err = None
    for i in range(attempts):
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and i < attempts - 1:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # pragma: no cover


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's API-level default region: CreateBucket rejects an explicit
        # LocationConstraint of "us-east-1", so the literal here pins the API call's shape,
        # not this resource, to a region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=name)
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
    objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
    if objs:
        failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _kinesis_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-fh-kds-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    deadline = time.monotonic() + 120.0
    arn = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            arn = desc["StreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError(f"Kinesis stream {name} did not become ACTIVE in time")
    return name, arn


def _basic_s3_dest(bucket_arn: str, role_arn: str) -> dict:
    return {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }


def _wait_stream_active(ctx, name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(
                f"delivery stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}"
            )
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
