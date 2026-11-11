"""s3-notification-suffix-filter-mismatch-no-delivery-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "s3-notification-suffix-filter-mismatch-no-delivery-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key that does not match the .csv suffix filter sends no message to the queue, while a
    matching key on the same bucket and configuration is delivered."""
    s3 = ctx.client("s3")
    bucket_name = _create_bucket(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_s3(ctx, queue_url, queue_arn, bucket_name)

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": queue_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "suffix", "Value": ".csv"}]}
                    },
                }
            ]
        },
    )

    # Calibration: measure how long a matching key takes to arrive on this wiring, right
    # now, so the absence window below is bounded by a demonstrated latency rather than a
    # guess.
    calibration_key = "reports/calibration.csv"
    t_calib = time.monotonic()
    s3.put_object(Bucket=bucket_name, Key=calibration_key, Body=b"a,b,c\n1,2,3\n")
    calibration_records = _poll_for_records(ctx, queue_url, timeout_s=90.0)
    latency_s = time.monotonic() - t_calib
    assert any(r["s3"]["object"]["key"] == calibration_key for r in calibration_records), (
        f"calibration key (matching suffix) was not delivered: {calibration_records}"
    )

    mismatched_key = "reports/notes.txt"
    s3.put_object(Bucket=bucket_name, Key=mismatched_key, Body=b"plain text notes")

    # Bound the negative wait at >= 3x the latency this wiring was just measured to need,
    # floored so a very fast account still gets a real window.
    window_s = max(3.0 * latency_s, 25.0)
    records = _drain_for(ctx, queue_url, duration_s=window_s)
    assert not any(r["s3"]["object"]["key"] == mismatched_key for r in records), (
        f"suffix-mismatched key was delivered within the {window_s:.0f}s window: {records}"
    )

    # Positive control: same bucket/config, a key that DOES match the suffix — proves the
    # filter was not left broken or stuck by the absence window above.
    matching_key = "reports/monthly.csv"
    s3.put_object(Bucket=bucket_name, Key=matching_key, Body=b"a,b,c\n1,2,3\n")
    control_records = _poll_for_records(ctx, queue_url, timeout_s=90.0)
    assert any(r["s3"]["object"]["key"] == matching_key for r in control_records), (
        f"positive control (matching suffix) was not delivered: {control_records}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-s3neg-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", [])
            ]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    return bucket_name


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-s3neg-q-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"simparity-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _set_queue_policy_for_s3(ctx, queue_url: str, queue_arn: str, bucket_name: str):
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Notify",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket_name}"}
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _poll_for_records(ctx, queue_url: str, timeout_s: float = 90.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                collected.append(rec)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return collected

    _wait_for_effect(
        probe,
        lambda recs: len(recs) > 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"S3 event delivered to queue {queue_url}",
    )
    return collected


def _drain_for(ctx, queue_url: str, duration_s: float) -> list[dict[str, Any]]:
    """Actively receive from the queue for a bounded window, collecting whatever
    arrives (used to assert absence over the full window, not a fixed sleep)."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        remaining = max(0, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                collected.append(rec)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if not resp.get("Messages") and remaining == 0:
            break
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
