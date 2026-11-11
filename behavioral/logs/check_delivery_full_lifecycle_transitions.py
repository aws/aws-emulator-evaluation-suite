"""delivery-full-lifecycle-transitions."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivery-full-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery links a source+destination into an active delivery visible via
    GetDelivery and DescribeDeliveries; DeleteDelivery tears it down and it disappears
    from DescribeDeliveries."""
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

    create_resp = logs.create_delivery(
        deliverySourceName=source_name,
        deliveryDestinationArn=dest_arn,
        tags={"sim2real": CHECK},
    )
    delivery = create_resp["delivery"]
    delivery_id = delivery["id"]
    assert delivery["deliverySourceName"] == source_name, (
        f"expected deliverySourceName {source_name!r}, got {delivery['deliverySourceName']!r}"
    )
    assert delivery["deliveryDestinationArn"] == dest_arn, (
        f"expected deliveryDestinationArn {dest_arn!r}, got {delivery['deliveryDestinationArn']!r}"
    )
    assert delivery["deliveryDestinationType"] == "CWL", (
        f"expected deliveryDestinationType 'CWL' (derived from the CWL destination), "
        f"got {delivery['deliveryDestinationType']!r}"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))

    got = logs.get_delivery(id=delivery_id)["delivery"]
    assert got["id"] == delivery_id, f"GetDelivery returned id {got['id']!r}, expected {delivery_id!r}"
    assert got["deliverySourceName"] == source_name, (
        f"GetDelivery deliverySourceName {got['deliverySourceName']!r} != {source_name!r}"
    )

    _poll_until(
        lambda: _find_delivery_id(logs, delivery_id),
        lambda found: found is True,
        timeout_s=30.0,
    )

    logs.delete_delivery(id=delivery_id)
    _wait_for_not_found(lambda: logs.get_delivery(id=delivery_id))
    _poll_until(
        lambda: _find_delivery_id(logs, delivery_id),
        lambda found: found is False,
        timeout_s=30.0,
    )

    # A mutation on the now-dead id must also fail, not just a read.
    second_delete_code, second_delete_message = _expect_error(lambda: logs.delete_delivery(id=delivery_id))
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected second DeleteDelivery on a torn-down id to raise ResourceNotFoundException, "
        f"got {second_delete_code!r}"
    )
    expected = "Requested Delivery does not exist in this account."
    assert second_delete_message == expected, (
        f"expected message {expected!r}, got {second_delete_message!r}"
    )


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


def _wait_for_not_found(fn: Callable[[], Any], timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
            code = None
        except ClientError as e:
            code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        last_code = code
        time.sleep(interval_s)
    raise AssertionError(f"expected ResourceNotFoundException, got {last_code!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _find_delivery_id(logs_client, delivery_id: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = logs_client.describe_deliveries(**kwargs)
        for d in resp.get("deliveries", []):
            if d.get("id") == delivery_id:
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-logs-src-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint --
    # this is an S3 API quirk, not a hardcoded target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
