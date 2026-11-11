"""create-delivery-duplicate-conflict-fails."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-delivery-duplicate-conflict-fails"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateDelivery for the same source and destination returns the same delivery id and exactly
    one delivery exists for the pair; after DeleteDelivery, GetDelivery and a second delete raise
    ResourceNotFoundException with the exact message."""
    logs = ctx.client("logs")

    bucket_name, bucket_arn = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-behav-cddup-src-")
    logs.put_delivery_source(name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS")
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-cddup-lg-")
    dest_name = ctx.unique_name("sim2real-behav-cddup-dst-")
    dest_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    create_resp = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    delivery_id = create_resp["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))

    # On real AWS a duplicate CreateDelivery for the same source/destination pair is accepted
    # idempotently and returns the *same* delivery that already exists; no second/distinct
    # pipeline is created for the pair.
    dup_resp = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    dup_id = dup_resp["delivery"]["id"]
    if dup_id != delivery_id:
        ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=dup_id)))
    assert dup_id == delivery_id, (
        f"duplicate CreateDelivery for the same source/destination pair created a new "
        f"delivery {dup_id} instead of idempotently returning the original delivery {delivery_id}"
    )

    # Only the original delivery must exist for this source/destination pair.
    described = _collect_all(logs.describe_deliveries, "deliveries")
    matching = [
        d
        for d in described
        if d.get("deliverySourceName") == source_name and d.get("deliveryDestinationArn") == dest_arn
    ]
    assert len(matching) == 1, f"expected exactly one delivery for the pair, found {len(matching)}"
    assert matching[0]["id"] == delivery_id, (
        f"expected the sole delivery for the pair to be the original {delivery_id}, "
        f"found {matching[0]['id']}"
    )

    # The delete already happens in cleanup but was otherwise unasserted: prove it is gone via
    # an independent read, and that a second delete on the deleted id also fails.
    logs.delete_delivery(id=delivery_id)
    code, msg = _error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetDelivery on a deleted delivery to be ResourceNotFoundException, got {code!r} {msg!r}"
    )
    assert msg == "Requested Delivery does not exist in this account.", (
        f"unexpected GetDelivery message for a deleted delivery: {msg!r}"
    )
    code, msg = _error(lambda: logs.delete_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", (
        f"expected a second DeleteDelivery on the same id to be ResourceNotFoundException, "
        f"got {code!r} {msg!r}"
    )
    assert msg == "Requested Delivery does not exist in this account.", (
        f"unexpected DeleteDelivery message for a deleted delivery: {msg!r}"
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


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _collect_all(call, resp_key: str, **kwargs) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = call(**params)
        items.extend(resp.get(resp_key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-cddup-b-").lower().replace("_", "-")
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
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
