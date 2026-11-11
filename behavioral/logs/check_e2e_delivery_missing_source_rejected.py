"""e2e-delivery-missing-source-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-delivery-missing-source-rejected"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery referencing a nonexistent delivery source is rejected, no delivery is
    created, and the same call succeeds once a real delivery source is put in place (control).
    """
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    dst_log_group = ctx.unique_name("sim2real-behav-delivery-neg-dst-")
    logs.create_log_group(logGroupName=dst_log_group)
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_log_group(logGroupName=dst_log_group)))
    dst_arn = _log_group_arn(logs, dst_log_group)

    dest_name = ctx.unique_name("sim2real-behav-delivery-neg-dest-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationConfiguration={"destinationResourceArn": dst_arn},
    )
    dest_arn = dest["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery_destination(name=dest_name)))

    bogus_source_name = ctx.unique_name("sim2real-behav-delivery-nonexistent-src-")

    code, message = _error(
        lambda: logs.create_delivery(
            deliverySourceName=bogus_source_name, deliveryDestinationArn=dest_arn
        )
    )
    assert code == "ResourceNotFoundException", code
    assert message == "Requested Delivery Source does not exist in this account.", message

    # Scoped to this check's own source name and fresh destination: other deliveries in the
    # account come and go.
    stray = [
        d for d in _all_deliveries(logs)
        if d.get("deliverySourceName") == bogus_source_name
        or d.get("deliveryDestinationArn") == dest_arn
    ]
    assert not stray, f"the rejected CreateDelivery left deliveries behind: {stray!r}"

    # Positive control: with a real source the identical call succeeds.
    bucket_name = ctx.unique_name("sim2real-behav-delivery-neg-src-").lower()
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _ignore(lambda: s3.delete_bucket(Bucket=bucket_name)))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    real_source_name = ctx.unique_name("sim2real-behav-delivery-real-src-")
    logs.put_delivery_source(
        name=real_source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery_source(name=real_source_name)))

    created = logs.create_delivery(
        deliverySourceName=real_source_name, deliveryDestinationArn=dest_arn
    )
    delivery_id = created["delivery"]["id"]
    assert created["delivery"]["deliverySourceName"] == real_source_name
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_delivery(id=delivery_id)))

    confirm = logs.get_delivery(id=delivery_id)["delivery"]
    assert confirm["deliverySourceName"] == real_source_name

    logs.delete_delivery(id=delivery_id)
    code, message = _error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", code
    assert message == "Requested Delivery does not exist in this account.", message

    logs.delete_delivery_source(name=real_source_name)
    code, message = _error(lambda: logs.get_delivery_source(name=real_source_name))
    assert code == "ResourceNotFoundException", code
    assert message == "Requested Delivery Source does not exist in this account.", message

    logs.delete_delivery_destination(name=dest_name)
    code, message = _error(lambda: logs.get_delivery_destination(name=dest_name))
    assert code == "ResourceNotFoundException", code
    assert message == "Requested Delivery Destination does not exist in this account.", message


def _create_bucket(s3_client: Any, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _all_deliveries(logs_client: Any) -> list:
    """Every page of DescribeDeliveries."""
    out, token = [], None
    while True:
        page = logs_client.describe_deliveries(**({"nextToken": token} if token else {}))
        out.extend(page.get("deliveries", []))
        token = page.get("nextToken")
        if not token:
            return out


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
