"""events-rule-role-trusts-events-service."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "events-rule-role-trusts-events-service"
GROUP = "permission-boundary"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutEvents through a rule whose target role trusts events.amazonaws.com is accepted and the event's
    marker lands in the Firehose stream's S3 destination."""
    events = ctx.client("events")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, "sim2real-eb-ok-")
    fh_role_arn = _create_role(ctx, "firehose.amazonaws.com", _s3_write_policy(bucket))
    stream_name = ctx.unique_name("sim2real-eb-fh-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": fh_role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": "sim2real/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(firehose, stream_name)
    stream_arn = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]

    events_role_arn = _create_role(
        ctx,
        "events.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": stream_arn}
            ],
        },
    )

    rule_name = ctx.unique_name("sim2real-eb-rule-")
    source = ctx.unique_name("sim2real.source.")
    detail_type = "sim2real-test-event"
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": stream_arn, "RoleArn": events_role_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    # EventBridge does not retry a target invocation that fails because the role has not yet
    # propagated -- a send that races propagation is lost for good, not just delayed. So a single
    # unconditional pre-send sleep is not just a style violation, it is a genuine flake: too short
    # and the send is silently dropped, and there is no client-observable signal for cross-service
    # IAM propagation to poll on instead. The only bounded, evidence-based option is to retry the
    # send itself across several windows, each long enough to observe a delivery if that attempt's
    # invocation succeeded: Firehose only flushes to S3 every 60s
    # (BufferingHints.IntervalInSeconds), so each window must clear that comfortably or a
    # genuinely-successful attempt would be mistaken for a lost one.
    deadline = time.monotonic() + 240
    attempt_window_s = 80.0
    marker = None
    body = None
    while body is None:
        marker = ctx.unique_name("sim2real-marker-")
        put_resp = events.put_events(
            Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
        )
        assert put_resp["FailedEntryCount"] == 0, f"expected 0 failed entries, got {put_resp}"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"marker {marker!r} never observed in S3 within the 240s retry budget")
        body = _s3_body_with_marker(s3, bucket, "sim2real/", marker, timeout_s=min(attempt_window_s, remaining))
    assert marker in body, f"marker {marker!r} never observed in delivered S3 object body: {body!r}"


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    # Cleanups run last-registered first: the inline policy goes before its role.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _s3_write_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectAcl"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }


def _create_delivery_stream_with_retry(firehose, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")


def _wait_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} never became ACTIVE (last status={status})")


def _s3_body_with_marker(s3, bucket: str, prefix: str, marker: str, timeout_s: float) -> str | None:
    """Return the first object body under prefix that carries marker, or None at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
            if marker in body:
                return body
        if time.monotonic() >= deadline:
            return None
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
