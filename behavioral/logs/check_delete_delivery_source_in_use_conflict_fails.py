"""delete-delivery-source-in-use-conflict-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-delivery-source-in-use-conflict-fails"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliverySource on a source an active delivery references raises ConflictException with its exact
    message and the source remains; after the delivery is removed, the delete succeeds and both a re-delete
    and a read raise ResourceNotFoundException."""
    logs = ctx.client("logs")
    owner_tags = {"Sim2RealOwner": "behavioral-suite"}

    bucket_name, bucket_arn = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-behav-cdsrc-")
    logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS", tags=owner_tags
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-cdlg-")
    dest_name = ctx.unique_name("sim2real-behav-cddst-")
    dest_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags=owner_tags,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    create_resp = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn, tags=owner_tags
    )
    delivery_id = create_resp["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))

    code, message = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == _SOURCE_IN_USE, f"unexpected in-use message {message!r}"

    # The source must still exist -- the failed delete must not have partially applied.
    still_there = logs.get_delivery_source(name=source_name)
    assert still_there["deliverySource"]["name"] == source_name, (
        f"expected {source_name!r} to still exist after the rejected delete, "
        f"got {still_there['deliverySource']!r}"
    )

    # Restore: once the referencing delivery is gone, the identical delete call succeeds
    # (positive control -- this is not "DeleteDeliverySource always fails").
    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_source(name=source_name)

    # The deleted source is not a valid target for a further delete either.
    code_redelete, msg_redelete = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code_redelete == "ResourceNotFoundException", (
        f"expected a second delete of the already-deleted source to fail with "
        f"ResourceNotFoundException, got {code_redelete}"
    )
    assert msg_redelete == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_redelete!r}"

    # Terminal: an independent read (not the delete itself) confirms the source is gone.
    code_after, msg_after = _error(lambda: logs.get_delivery_source(name=source_name))
    assert code_after == "ResourceNotFoundException", (
        f"expected the source to be gone by an independent read after the restored delete "
        f"succeeded, got {code_after}"
    )
    assert msg_after == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_after!r}"


_SOURCE_NOT_FOUND = "Requested Delivery Source does not exist in this account."
_SOURCE_IN_USE = (
    "Could not delete this Delivery Source as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-cdsrc-b-").lower().replace("_", "-")
    region = ctx.region
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: s3.delete_bucket(Bucket=name)))
    return name, f"arn:aws:s3:::{name}"


def _create_log_group(ctx, prefix: str):
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
