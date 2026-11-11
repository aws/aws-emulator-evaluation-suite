"""get-delivery-reflects-actual-record-fields-after-events-flow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-delivery-reflects-actual-record-fields-after-events-flow"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDelivery for an S3 delivery source paired with a CloudWatch Logs destination returns the created id,
    source, destination ARN, type CWL and the default recordFields from CreateDelivery; after deletion it
    raises ResourceNotFoundException with its exact message.
    """
    logs = ctx.client("logs")
    ctx.client("s3")

    dest_log_group = ctx.unique_name("sim2real-dlvy-dest-lg")
    logs.create_log_group(logGroupName=dest_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=dest_log_group))
    dest_log_group_arn = logs.describe_log_groups(logGroupNamePrefix=dest_log_group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-dlvy-dest")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_log_group_arn},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    bucket_name = _create_s3_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    src_name = ctx.unique_name("sim2real-dlvy-src")
    logs.put_delivery_source(name=src_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS")
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=src_name))

    # recordFields is optional on CreateDelivery -- when omitted, CloudWatch
    # Logs applies the log type's default field set (rather than an empty
    # placeholder). Rely on that default instead of guessing exact valid
    # field names, and assert GetDelivery reflects a real, non-empty set that
    # matches what CreateDelivery actually returned.
    created = logs.create_delivery(
        deliverySourceName=src_name,
        deliveryDestinationArn=dest_arn,
    )["delivery"]
    delivery_id = created["id"]
    ctx.on_cleanup(lambda: _safe_delete_delivery(logs, delivery_id))
    created_record_fields = created.get("recordFields") or []
    assert created_record_fields, f"expected CreateDelivery to populate default recordFields, got {created}"

    fetched = logs.get_delivery(id=delivery_id)["delivery"]
    assert fetched["id"] == delivery_id
    assert fetched["deliverySourceName"] == src_name
    assert fetched["deliveryDestinationArn"] == dest_arn
    assert fetched["deliveryDestinationType"] == "CWL", fetched
    assert fetched["recordFields"] == created_record_fields, fetched
    assert fetched["arn"], "delivery arn must not be empty"

    logs.delete_delivery(id=delivery_id)
    code, message = _error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected_message = "Requested Delivery does not exist in this account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_delivery(logs, delivery_id: str) -> None:
    try:
        logs.delete_delivery(id=delivery_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-logs-dlvy-src").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    return bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
