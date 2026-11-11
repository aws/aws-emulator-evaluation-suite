"""delete-delivery-source-in-use-conflict."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-delivery-source-in-use-conflict"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliverySource on a source an active delivery references raises ConflictException with its exact
    message and the source remains; after the delivery is removed, the delete succeeds and it reads
    ResourceNotFoundException."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    log_group, dest_name, dest_arn = _create_delivery_destination(ctx, logs)
    bucket, source_name, delivery_id = _create_delivery(ctx, logs, s3, dest_arn)

    code, message = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code == "ConflictException", (
        f"expected ConflictException deleting a delivery source still referenced "
        f"by an active delivery, got {code}"
    )
    assert message == _SOURCE_IN_USE, f"unexpected in-use message {message!r}"

    # The rejected call must not have partially applied: the source is still visible.
    src = logs.get_delivery_source(name=source_name)["deliverySource"]
    assert src["name"] == source_name, (
        f"expected delivery source {source_name!r} to survive the rejected delete, "
        f"got {src.get('name')!r}"
    )

    # Positive control: once the referencing delivery is gone, the identical
    # delete call succeeds and the source is independently confirmed gone.
    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_source(name=source_name)
    code_after, msg_after = _error(lambda: logs.get_delivery_source(name=source_name))
    assert code_after == "ResourceNotFoundException", (
        f"expected the now-unreferenced source to be deleted and read back as "
        f"ResourceNotFoundException, got {code_after}"
    )
    assert msg_after == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_after!r}"


_SOURCE_NOT_FOUND = "Requested Delivery Source does not exist in this account."
_SOURCE_IN_USE = (
    "Could not delete this Delivery Source as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)


def _create_delivery_destination(ctx, logs: Any) -> tuple[str, str, str]:
    log_group = ctx.unique_name("sim2real-behav-dstlg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-behav-dest-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_destination(name=dest_name)))
    return log_group, dest_name, dest["arn"]


def _create_delivery(ctx, logs: Any, s3: Any, dest_arn: str) -> tuple[str, str, str]:
    bucket = ctx.unique_name("sim2real-behav-dlvsrc-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    source_name = ctx.unique_name("sim2real-behav-src-")
    logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_source(name=source_name)))

    delivery = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn
    )["delivery"]
    delivery_id = delivery["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=delivery_id)))
    return bucket, source_name, delivery_id


def _create_bucket(s3: Any, bucket: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) fn() raised. A success raises: a target that accepts a call real AWS
    refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn: Callable[[], Any]) -> None:
    """Cleanup is idempotent: the check body may have already deleted this resource."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
