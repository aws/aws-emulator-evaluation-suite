"""put-record-invalid-source-kinesis-backed-stream."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-invalid-source-kinesis-backed-stream"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord against a Kinesis-sourced delivery stream is refused with
    InvalidArgumentException (direct-PUT is disallowed once a Kinesis source is wired up),
    while the identical call against a DirectPut stream (positive control) succeeds."""
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    role_arn = _iam_role_for_firehose(ctx)
    _wait_role_ready(ctx, role_arn, bucket_arn)
    _kinesis_name, kinesis_arn = _kinesis_stream(ctx)

    firehose = ctx.client("firehose")

    direct_name = ctx.unique_name("sim2real-fh-direct-")
    firehose.create_delivery_stream(
        DeliveryStreamName=direct_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
        Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=direct_name))

    kinesis_backed_name = ctx.unique_name("sim2real-fh-kdssrc-")
    firehose.create_delivery_stream(
        DeliveryStreamName=kinesis_backed_name,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": kinesis_arn, "RoleARN": role_arn},
        ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
        Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=kinesis_backed_name))

    _wait_stream_active(ctx, direct_name)
    kdesc = _wait_stream_active(ctx, kinesis_backed_name)
    actual_source_arn = kdesc["Source"]["KinesisStreamSourceDescription"]["KinesisStreamARN"]
    assert actual_source_arn == kinesis_arn, (
        f"expected delivery stream source to be {kinesis_arn}, got {actual_source_arn}"
    )

    # Positive control: a DirectPut stream accepts PutRecord.
    ok = firehose.put_record(DeliveryStreamName=direct_name, Record={"Data": b"direct-put-ok"})
    assert ok["RecordId"], f"expected PutRecord against a DirectPut stream to return a RecordId, got {ok}"

    # Negative: the Kinesis-sourced stream must refuse direct PutRecord calls. Firehose
    # rejects direct-put calls against a KinesisStreamAsSource delivery stream with
    # InvalidArgumentException (InvalidSourceException is reserved for a different scenario:
    # non-CloudWatch-Logs callers when CloudWatch Logs decompression is enabled).
    try:
        firehose.put_record(
            DeliveryStreamName=kinesis_backed_name, Record={"Data": b"should-be-rejected"}
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "InvalidArgumentException", (
            f"expected InvalidArgumentException for direct PutRecord on a Kinesis-sourced "
            f"stream, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
            f"unexpected refusal message {message!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidArgumentException for PutRecord on a Kinesis-sourced stream"
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
    )
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


def _wait_role_ready(ctx, role_arn: str, bucket_arn: str, timeout_s: float = 120.0) -> None:
    """Poll IAM role assumability from Firehose's perspective by attempting (and immediately
    discarding) a disposable delivery stream, retrying while Firehose reports the role as not
    yet assumable. This keeps the two delivery streams under test from flaking on IAM
    propagation lag rather than on the direct-PUT-rejection semantics being tested."""
    firehose = ctx.client("firehose")
    probe_name = ctx.unique_name("sim2real-fh-warmup-")
    dest_config = _basic_s3_dest(bucket_arn, role_arn)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=probe_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    # Firehose refuses DeleteDeliveryStream while the stream is CREATING, so the warm-up
    # stream is deleted at teardown by a helper that waits for a deletable state.
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, probe_name))


def _delete_stream_and_wait(ctx, name: str, timeout_s: float = 420.0) -> None:
    """Poll to a deletable state, delete, then poll until the stream is actually gone.
    DeleteDeliveryStream returns while still DELETING and is refused while CREATING."""
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        state = desc["DeliveryStreamStatus"]
        if state != "DELETING":
            try:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"LEAK: delivery stream {name} still {state} after {timeout_s}s")
        time.sleep(5)


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
    # that names it, so the constraint is only passed for every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-purpose", "Value": CHECK}]}
    )
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
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real-purpose": CHECK})
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
