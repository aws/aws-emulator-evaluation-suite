"""delete-delivery-source-with-active-delivery-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-delivery-source-with-active-delivery-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliverySource is rejected with ConflictException while a delivery still
    references the source; the source is untouched. Once the referencing delivery is removed,
    the identical delete call succeeds (positive control)."""
    logs = ctx.client("logs")

    bucket_name, bucket_arn = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-dsrc-")
    logs.put_delivery_source(
        name=source_name,
        resourceArn=bucket_arn,
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_source(name=source_name)))

    log_group_name, log_group_arn = _create_log_group(ctx)
    dest_name = ctx.unique_name("sim2real-ddest-")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_destination(name=dest_name)))

    delivery_id = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)[
        "delivery"
    ]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=delivery_id)))

    # Precondition broken: an active delivery still references this source.
    code, message = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == _SOURCE_IN_USE, f"unexpected in-use message {message!r}"

    # The forbidden effect did not happen: the source is still present.
    still_there = logs.get_delivery_source(name=source_name)["deliverySource"]
    assert still_there["name"] == source_name, f"expected {source_name!r} to remain, got {still_there!r}"

    # Positive control: once the referencing delivery is removed, the delete succeeds.
    logs.delete_delivery(id=delivery_id)
    logs.delete_delivery_source(name=source_name)
    code_after, msg_after = _error(lambda: logs.get_delivery_source(name=source_name))
    assert code_after == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_after}"
    assert msg_after == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_after!r}"

    # Gone means gone: a further mutation on the deleted source also fails, not just the read.
    code_delete_again, msg_delete_again = _error(lambda: logs.delete_delivery_source(name=source_name))
    assert code_delete_again == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted source, got {code_delete_again}"
    )
    assert msg_delete_again == _SOURCE_NOT_FOUND, f"unexpected not-found message {msg_delete_again!r}"


_SOURCE_NOT_FOUND = "Requested Delivery Source does not exist in this account."
_SOURCE_IN_USE = (
    "Could not delete this Delivery Source as it is currently in use. "
    "Please delete any Deliveries that reference this resource and try again."
)

def _error(fn):
    """The (code, message) fn() raised; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-dcrej-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=name)))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]})
    return name, f"arn:aws:s3:::{name}"


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=name)))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
