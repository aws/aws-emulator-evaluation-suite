"""delivery-destination-delete-blocked-by-dependent-delivery-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delivery-destination-delete-blocked-by-dependent-delivery-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliveryDestination is rejected with ConflictException while a Delivery
    still references the destination; a destination cannot be torn down out from under
    an active pairing."""
    logs = ctx.client("logs")

    bucket_name, bucket_arn = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-dsrc-")
    logs.put_delivery_source(
        name=source_name,
        resourceArn=bucket_arn,
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))

    _, log_group_arn = _create_log_group(ctx)
    dest_name = ctx.unique_name("sim2real-ddst-")
    dest_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"sim2real": CHECK},
    )
    dest_arn = dest_resp["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))

    delivery_id = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))

    code, message = _expect_error(lambda: logs.delete_delivery_destination(name=dest_name))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "Could not delete this Delivery Destination as it is currently in use. Please delete any Deliveries that reference this resource and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # confirm the destination is still fully intact after the rejected delete
    got = logs.get_delivery_destination(name=dest_name)["deliveryDestination"]
    assert got["name"] == dest_name, f"expected {dest_name!r} to survive the rejected delete, got {got!r}"

    # tearing down the dependent delivery first must unblock the delete
    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_destination(name=dest_name)

    # independent read at the destination: the delete that succeeded actually took effect
    gone_code, gone_message = _expect_error(lambda: logs.get_delivery_destination(name=dest_name))
    assert gone_code == "ResourceNotFoundException", (
        f"expected the destination to be gone once its only dependent delivery is removed, "
        f"got {gone_code!r}"
    )
    expected = "Requested Delivery Destination does not exist in this account."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


def _expect_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-logs-src-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name, f"arn:aws:s3:::{name}"


def _create_log_group(ctx) -> tuple[str, str]:
    logs_client = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-lg-")
    logs_client.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs_client.delete_log_group(logGroupName=name))
    arn = logs_client.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
