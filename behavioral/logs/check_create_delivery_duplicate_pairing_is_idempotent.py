"""create-delivery-duplicate-pairing-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-delivery-duplicate-pairing-is-idempotent"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-pairing a delivery source with the same destination returns the same delivery id with exactly one
    delivery for the pair, and deleted deliveries read ResourceNotFoundException with the exact message; a
    different destination yields a distinct delivery id."""
    logs = ctx.client("logs")
    tagset = {"sim2real-behav": CHECK}

    bucket_name, bucket_arn = _create_bucket(ctx, tagset)
    source_name = ctx.unique_name("sim2real-dsrc-")
    logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS", tags=tagset
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_source(name=source_name)))

    log_group_name, log_group_arn = _create_log_group(ctx, tagset)
    dest_name = ctx.unique_name("sim2real-ddest-")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags=tagset,
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_destination(name=dest_name)))

    first_id = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn, tags=tagset
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=first_id)))

    # Re-pairing the SAME source with the SAME destination is idempotent: it returns the SAME
    # delivery id rather than raising ConflictException or minting a second, independent one.
    second_id = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn, tags=tagset
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=second_id)))
    assert second_id == first_id, "expected re-pairing to return the SAME, idempotent delivery"

    matching = [
        d
        for d in logs.describe_deliveries()["deliveries"]
        if d["deliverySourceName"] == source_name and d["deliveryDestinationArn"] == dest_arn
    ]
    assert len(matching) == 1, f"expected exactly one delivery for this pairing, found {len(matching)}"

    # Deleting the delivery for this pairing removes it entirely (there is no second delivery
    # to remain behind).
    logs.delete_delivery(id=first_id)
    code, msg = _error(lambda: logs.get_delivery(id=first_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "Requested Delivery does not exist in this account.", f"unexpected message: {msg!r}"

    code, msg = _error(lambda: logs.get_delivery(id=second_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "Requested Delivery does not exist in this account.", f"unexpected message: {msg!r}"

    # A mutation on the deleted id must also 404, not just a read.
    code, msg = _error(
        lambda: logs.update_delivery_configuration(id=first_id, recordFields=[])
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateDeliveryConfiguration on a deleted delivery should 404, got {code!r} {msg!r}"
    )
    assert msg == "Requested Delivery does not exist in this account.", f"unexpected message: {msg!r}"

    # Positive control: pairing the SAME source with a DIFFERENT destination creates a
    # genuinely distinct, independent delivery.
    log_group_name2, log_group_arn2 = _create_log_group(ctx, tagset)
    dest_name2 = ctx.unique_name("sim2real-ddest2-")
    dest_arn2 = logs.put_delivery_destination(
        name=dest_name2,
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn2},
        tags=tagset,
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_destination(name=dest_name2)))

    third_id = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn2, tags=tagset
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=third_id)))
    assert third_id not in (first_id, second_id), (
        f"expected a distinct delivery id for a different destination, got {third_id} "
        f"which collides with an existing pairing's id"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(ctx, tagset):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ddup-")
    kwargs = {"Bucket": name}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tagset.items()]})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=name)))
    return name, f"arn:aws:s3:::{name}"


def _create_log_group(ctx, tagset):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, tags=tagset)
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=name)))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

