"""delete-delivery-source-in-use-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-delivery-source-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliverySource and DeleteDeliveryDestination on a pair an active delivery references each raise
    ConflictException with the exact message and leave the resource; after the delivery is removed, both
    deletes succeed and each reads ResourceNotFoundException."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-dlv-inuse-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    source_name = ctx.unique_name("sim2real-inuse-source-")
    logs.put_delivery_source(
        name=source_name,
        resourceArn=bucket_arn,
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))

    dest_group_name = ctx.unique_name("sim2real-inuse-dest-lg-")
    logs.create_log_group(logGroupName=dest_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=dest_group_name))
    dest_group_arn = logs.describe_log_groups(logGroupNamePrefix=dest_group_name)["logGroups"][0]["arn"]

    destination_name = ctx.unique_name("sim2real-inuse-destination-")
    dest_arn = logs.put_delivery_destination(
        name=destination_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_group_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=destination_name)))

    delivery_id = logs.create_delivery(
        deliverySourceName=source_name,
        deliveryDestinationArn=dest_arn,
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))

    # Precondition broken: an active delivery still references both the source and the destination.
    code, message = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code == "ConflictException", f"expected ConflictException deleting an in-use source, got {code}"
    assert message == _SOURCE_IN_USE, f"unexpected in-use message {message!r}"
    src = logs.get_delivery_source(name=source_name)["deliverySource"]
    assert src["name"] == source_name, "the rejected delete must not have torn down the source"

    code, message = _error(lambda: logs.delete_delivery_destination(name=destination_name))
    assert code == "ConflictException", (
        f"expected ConflictException deleting an in-use destination, got {code}"
    )
    assert message == _DEST_IN_USE, f"unexpected in-use message {message!r}"
    dest = logs.get_delivery_destination(name=destination_name)["deliveryDestination"]
    assert dest["name"] == destination_name, "the rejected delete must not have torn down the destination"

    # Restore: remove the referencing delivery, then the identical calls must now succeed.
    logs.delete_delivery(id=delivery_id)

    logs.delete_delivery_source(name=source_name)
    code_after, msg_after = _error(lambda: logs.get_delivery_source(name=source_name))
    assert code_after == "ResourceNotFoundException", (
        f"source delete succeeded but a read still finds it, got {code_after}"
    )
    assert msg_after == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_after!r}"

    logs.delete_delivery_destination(name=destination_name)
    code_after, msg_after = _error(lambda: logs.get_delivery_destination(name=destination_name))
    assert code_after == "ResourceNotFoundException", (
        f"destination delete succeeded but a read still finds it, got {code_after}"
    )
    assert msg_after == _DEST_NOT_FOUND, f"unexpected not-found message {msg_after!r}"


_SOURCE_NOT_FOUND = "Requested Delivery Source does not exist in this account."
_SOURCE_IN_USE = (
    "Could not delete this Delivery Source as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)
_DEST_NOT_FOUND = "Requested Delivery Destination does not exist in this account."
_DEST_IN_USE = (
    "Could not delete this Delivery Destination as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)

def _error(fn):
    """The (code, message) fn() raised. A success raises: a target that accepts a call real AWS
    refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
