"""create-delivery-nonexistent-source-fails."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-delivery-nonexistent-source-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDelivery naming a nonexistent deliverySourceName raises ResourceNotFoundException and
    creates no delivery; the same destination accepts a delivery once a real source exists."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    log_group = ctx.unique_name("sim2real-behav-dstlg-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-behav-dest-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    missing_source_name = ctx.unique_name("sim2real-behav-nosuchsource-")

    code, msg = _error(
        lambda: logs.create_delivery(
            deliverySourceName=missing_source_name, deliveryDestinationArn=dest["arn"]
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for CreateDelivery with a nonexistent "
        f"deliverySourceName, got {code!r} {msg!r}"
    )
    assert msg == "Requested Delivery Source does not exist in this account.", (
        f"unexpected CreateDelivery message for a nonexistent source: {msg!r}"
    )

    # Scoped to this check's own source name and fresh destination: other deliveries in the
    # account come and go.
    stray = [
        d for d in _all_deliveries(logs)
        if d.get("deliverySourceName") == missing_source_name
        or d.get("deliveryDestinationArn") == dest["arn"]
    ]
    assert not stray, (
        f"CreateDelivery with a nonexistent source must create nothing, but DescribeDeliveries "
        f"lists {stray!r} for this source or destination"
    )

    # Positive control: with a real source the same destination accepts a delivery.
    bucket_name = ctx.unique_name("sim2real-behav-nosrc-ctrl-").lower()
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name))

    real_source_name = ctx.unique_name("sim2real-behav-realsource-")
    logs.put_delivery_source(
        name=real_source_name,
        resourceArn=f"arn:aws:s3:::{bucket_name}",
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=real_source_name))

    created = logs.create_delivery(
        deliverySourceName=real_source_name, deliveryDestinationArn=dest["arn"]
    )
    delivery_id = created["delivery"]["id"]
    ctx.on_cleanup(lambda: logs.delete_delivery(id=delivery_id))
    assert created["delivery"]["deliverySourceName"] == real_source_name, (
        f"positive control: CreateDelivery with a real source did not succeed as "
        f"expected: {created['delivery']!r}"
    )

    confirmed = logs.get_delivery(id=delivery_id)["delivery"]
    assert confirmed["id"] == delivery_id, (
        f"expected GetDelivery to return the delivery just created: "
        f"id={delivery_id!r} got={confirmed!r}"
    )
    assert confirmed["deliverySourceName"] == real_source_name, (
        f"expected GetDelivery to reflect the real source: "
        f"expected={real_source_name!r} got={confirmed.get('deliverySourceName')!r}"
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


def _create_bucket(s3_client: Any, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _delete_bucket(s3_client: Any, bucket_name: str) -> None:
    for obj in s3_client.list_objects_v2(Bucket=bucket_name).get("Contents", []):
        s3_client.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3_client.delete_bucket(Bucket=bucket_name)


def _all_deliveries(logs):
    """Every page of DescribeDeliveries."""
    out, token = [], None
    while True:
        page = logs.describe_deliveries(**({"nextToken": token} if token else {}))
        out.extend(page.get("deliveries", []))
        token = page.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
