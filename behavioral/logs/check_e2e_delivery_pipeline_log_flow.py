"""e2e-delivery-pipeline-log-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-delivery-pipeline-log-flow"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3-backed delivery source, log-group destination and delivery persist and link correctly,
    PutDeliverySource rejects a missing bucket, and each piece is gone after deletion.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/sal-cw-enabling.html
    """
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    dst_log_group = ctx.unique_name("sim2real-behav-delivery-dst-")
    logs.create_log_group(logGroupName=dst_log_group)
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_log_group(logGroupName=dst_log_group)))
    dst_arn = _log_group_arn(logs, dst_log_group)

    bucket_name = ctx.unique_name("sim2real-behav-delivery-src-").lower()
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _ignore(lambda: s3.delete_bucket(Bucket=bucket_name)))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    dest_name = ctx.unique_name("sim2real-behav-delivery-dest-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationConfiguration={"destinationResourceArn": dst_arn},
    )
    actual_dest_type = dest["deliveryDestination"]["deliveryDestinationType"]
    assert actual_dest_type == "CWL", f"expected deliveryDestinationType CWL, got {actual_dest_type!r}"
    dest_arn = dest["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery_destination(name=dest_name)))

    # PutDeliverySource validates that the referenced S3 bucket exists, not just the ARN shape.
    bogus_bucket_name = ctx.unique_name("sim2real-behav-delivery-missing-").lower()
    bogus_bucket_arn = f"arn:aws:s3:::{bogus_bucket_name}"
    bogus_src_name = ctx.unique_name("sim2real-behav-delivery-src-bogus-")
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery_source(name=bogus_src_name)))
    bogus_code, bogus_message = _error(
        lambda: logs.put_delivery_source(
            name=bogus_src_name, resourceArn=bogus_bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
        )
    )
    assert bogus_code == "ResourceNotFoundException", (
        f"expected PutDeliverySource to reject a resourceArn for a bucket that was never "
        f"created ({bogus_bucket_arn}) with ResourceNotFoundException, got {bogus_code!r}"
    )
    assert bogus_message == "The specified bucket does not exist", (
        f"unexpected PutDeliverySource message for a never-created bucket: {bogus_message!r}"
    )

    src_name = ctx.unique_name("sim2real-behav-delivery-src-")
    src = logs.put_delivery_source(
        name=src_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    actual_log_type = src["deliverySource"]["logType"]
    assert actual_log_type == "S3_SERVER_ACCESS_LOGS", (
        f"expected deliverySource logType S3_SERVER_ACCESS_LOGS, got {actual_log_type!r}"
    )
    actual_resource_arns = src["deliverySource"]["resourceArns"]
    assert actual_resource_arns == [bucket_arn], (
        f"expected deliverySource resourceArns [{bucket_arn}], got {actual_resource_arns!r}"
    )
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery_source(name=src_name)))

    created = logs.create_delivery(deliverySourceName=src_name, deliveryDestinationArn=dest_arn)
    delivery_id = created["delivery"]["id"]
    actual_src_name = created["delivery"]["deliverySourceName"]
    assert actual_src_name == src_name, f"expected deliverySourceName {src_name!r}, got {actual_src_name!r}"
    actual_dest_arn = created["delivery"]["deliveryDestinationArn"]
    assert actual_dest_arn == dest_arn, f"expected deliveryDestinationArn {dest_arn!r}, got {actual_dest_arn!r}"
    actual_created_dest_type = created["delivery"]["deliveryDestinationType"]
    assert actual_created_dest_type == "CWL", (
        f"expected created delivery's deliveryDestinationType CWL, got {actual_created_dest_type!r}"
    )
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery(id=delivery_id)))

    # Confirm the link was actually persisted server-side, not just echoed back.
    fetched = logs.get_delivery(id=delivery_id)["delivery"]
    assert fetched["id"] == delivery_id, f"expected GetDelivery id {delivery_id!r}, got {fetched['id']!r}"
    fetched_src_name = fetched["deliverySourceName"]
    assert fetched_src_name == src_name, f"expected persisted deliverySourceName {src_name!r}, got {fetched_src_name!r}"
    fetched_dest_arn = fetched["deliveryDestinationArn"]
    assert fetched_dest_arn == dest_arn, f"expected persisted deliveryDestinationArn {dest_arn!r}, got {fetched_dest_arn!r}"

    # The destination log group accepts and returns events.
    stream_name = ctx.unique_name("sim2real-behav-delivery-stream-")
    logs.create_log_stream(logGroupName=dst_log_group, logStreamName=stream_name)
    marker = ctx.unique_name("delivery-marker-")
    logs.put_log_events(
        logGroupName=dst_log_group,
        logStreamName=stream_name,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": marker}],
    )
    events = _poll_until(
        lambda: logs.get_log_events(
            logGroupName=dst_log_group, logStreamName=stream_name, startFromHead=True
        )["events"],
        lambda evts: any(marker in e["message"] for e in evts),
        timeout_s=30,
        interval_s=2,
    )
    assert any(marker in e["message"] for e in events), (
        f"expected marker {marker!r} in delivered events, got {[e['message'] for e in events]!r}"
    )

    logs.delete_delivery(id=delivery_id)
    delivery_code, delivery_message = _error(lambda: logs.get_delivery(id=delivery_id))
    assert delivery_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted delivery {delivery_id!r}, got {delivery_code!r}"
    )
    assert delivery_message == "Requested Delivery does not exist in this account.", (
        f"unexpected message reading deleted delivery {delivery_id!r}: {delivery_message!r}"
    )

    logs.delete_delivery_source(name=src_name)
    source_code, source_message = _error(lambda: logs.get_delivery_source(name=src_name))
    assert source_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted delivery source {src_name!r}, got {source_code!r}"
    )
    assert source_message == "Requested Delivery Source does not exist in this account.", (
        f"unexpected message reading deleted delivery source {src_name!r}: {source_message!r}"
    )

    logs.delete_delivery_destination(name=dest_name)
    dest_code, dest_message = _error(lambda: logs.get_delivery_destination(name=dest_name))
    assert dest_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted delivery destination {dest_name!r}, got {dest_code!r}"
    )
    assert dest_message == "Requested Delivery Destination does not exist in this account.", (
        f"unexpected message reading deleted delivery destination {dest_name!r}: {dest_message!r}"
    )


def _create_bucket(s3_client: Any, bucket_name: str, region: str) -> None:
    # CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if region == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _ignore(fn: Any) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "ResourceNotFoundException"):
            raise


def _log_group_arn(logs_client: Any, name: str) -> str:
    resp = logs_client.describe_log_groups(logGroupNamePrefix=name)
    for group in resp["logGroups"]:
        if group["logGroupName"] == name:
            return group["arn"]
    raise AssertionError(f"log group {name} not found via DescribeLogGroups")


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe: Any, predicate: Any, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
