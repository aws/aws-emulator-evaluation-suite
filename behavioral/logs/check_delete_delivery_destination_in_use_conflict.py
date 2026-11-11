"""delete-delivery-destination-in-use-conflict."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-delivery-destination-in-use-conflict"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliveryDestination on a destination an active delivery references raises ConflictException with
    its exact message and the destination remains; after the delivery is removed, the delete succeeds and it
    reads ResourceNotFoundException."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    # Positive control: deleting a destination with no active delivery
    # succeeds, so the later rejection is attributable to the dependency,
    # not to a target that rejects every DeleteDeliveryDestination call.
    _, control_dest_name, _ = _create_delivery_destination(ctx, logs)
    logs.delete_delivery_destination(name=control_dest_name)
    control_code, control_msg = _error(lambda: logs.get_delivery_destination(name=control_dest_name))
    assert control_code == "ResourceNotFoundException", (
        f"positive control: expected the unreferenced destination to be gone "
        f"after delete, got {control_code}"
    )
    assert control_msg == _DEST_NOT_FOUND, f"unexpected not-found message {control_msg!r}"
    log_group, dest_name, dest_arn = _create_delivery_destination(ctx, logs)
    bucket, source_name, delivery_id = _create_delivery(ctx, logs, s3, dest_arn)

    code, message = _error(lambda: logs.delete_delivery_destination(name=dest_name))
    assert code == "ConflictException", (
        f"expected ConflictException deleting a delivery destination still "
        f"referenced by an active delivery, got {code}"
    )
    assert message == _DEST_IN_USE, f"unexpected in-use message {message!r}"

    # The effect is absent: the destination is still visible and unaffected
    # by the rejected call.
    dest = logs.get_delivery_destination(name=dest_name)["deliveryDestination"]
    assert dest["name"] == dest_name

    # Restore: tearing down the dependent delivery must unblock the identical
    # delete call, which now succeeds.
    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_destination(name=dest_name)
    post_code, post_msg = _error(lambda: logs.get_delivery_destination(name=dest_name))
    assert post_code == "ResourceNotFoundException", (
        f"expected the destination to be gone after the dependency was "
        f"removed and delete retried, got {post_code}"
    )
    assert post_msg == _DEST_NOT_FOUND, f"unexpected not-found message {post_msg!r}"


_DEST_NOT_FOUND = "Requested Delivery Destination does not exist in this account."
_DEST_IN_USE = (
    "Could not delete this Delivery Destination as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)


def _create_delivery_destination(ctx, logs: Any) -> tuple[str, str, str]:
    log_group = ctx.unique_name("sim2real-behav-dstlg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-behav-dest-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))
    return log_group, dest_name, dest["arn"]


def _create_delivery(ctx, logs: Any, s3: Any, dest_arn: str) -> tuple[str, str, str]:
    bucket = ctx.unique_name("sim2real-behav-dlvdst-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    source_name = ctx.unique_name("sim2real-behav-src-")
    logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=source_name))

    delivery = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn
    )["delivery"]
    delivery_id = delivery["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))
    return bucket, source_name, delivery_id


def _create_bucket(s3: Any, bucket: str, region: str) -> None:
    # us-east-1 is a CreateBucket API quirk (LocationConstraint must be omitted
    # there), not a region this check pins itself to.
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


def _safe_call(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
