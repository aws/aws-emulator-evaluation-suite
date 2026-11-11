"""delivery-lifecycle-create-update-delete."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delivery-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery links a source and destination into a pipeline visible via
    GetDelivery/DescribeDeliveries, UpdateDeliveryConfiguration mutates it, and
    DeleteDelivery tears it down."""
    logs = ctx.client("logs")

    bucket_name, bucket_arn = _create_bucket(ctx, "sim2real-behav-dlsrc-b-")
    source_name = ctx.unique_name("sim2real-behav-dlsrc-")
    logs.put_delivery_source(
        name=source_name,
        resourceArn=bucket_arn,
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))

    # Use an S3 delivery destination rather than CWL: fieldDelimiter is only accepted for log
    # types whose output format supports delimited text, and S3_SERVER_ACCESS_LOGS only
    # supports JSON output, so UpdateDeliveryConfiguration(fieldDelimiter=...) is rejected with
    # ValidationException regardless of destination type. s3DeliveryConfiguration, by
    # contrast, is valid whenever the destination itself is an S3 bucket, independent of the
    # source's log type, so exercise that update path instead.
    dest_bucket_name, dest_bucket_arn = _create_bucket(ctx, "sim2real-behav-dldst-b-")
    dest_name = ctx.unique_name("sim2real-behav-dldst-")
    dest_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_bucket_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    create_resp = logs.create_delivery(
        deliverySourceName=source_name,
        deliveryDestinationArn=dest_arn,
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    delivery_id = create_resp["delivery"]["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery(id=delivery_id)))
    assert create_resp["delivery"]["deliverySourceName"] == source_name, (
        f"CreateDelivery response deliverySourceName mismatch: {create_resp['delivery']}"
    )
    assert create_resp["delivery"]["deliveryDestinationArn"] == dest_arn, (
        f"CreateDelivery response deliveryDestinationArn mismatch: {create_resp['delivery']}"
    )

    got = logs.get_delivery(id=delivery_id)
    assert got["delivery"]["id"] == delivery_id, f"GetDelivery returned wrong id: {got['delivery']}"
    assert got["delivery"]["deliveryDestinationType"] == "S3", (
        f"expected deliveryDestinationType=S3, got {got['delivery'].get('deliveryDestinationType')}"
    )

    described = _collect_all(logs.describe_deliveries, "deliveries")
    ids = {d["id"] for d in described}
    assert delivery_id in ids, f"{delivery_id} missing from DescribeDeliveries: {ids}"

    logs.update_delivery_configuration(
        id=delivery_id,
        s3DeliveryConfiguration={"suffixPath": "custom-suffix-path", "enableHiveCompatiblePath": False},
    )
    updated = logs.get_delivery(id=delivery_id)
    assert updated["delivery"].get("s3DeliveryConfiguration", {}).get("suffixPath") == "custom-suffix-path", (
        f"UpdateDeliveryConfiguration did not persist s3DeliveryConfiguration: {updated['delivery']}"
    )

    logs.delete_delivery(id=delivery_id)

    code, message = _expect_error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described_after = _collect_all(logs.describe_deliveries, "deliveries")
    assert delivery_id not in {d["id"] for d in described_after}, (
        "delivery still listed after DeleteDelivery"
    )

    mutate_code, mutate_message = _expect_error(
        lambda: logs.update_delivery_configuration(
            id=delivery_id,
            s3DeliveryConfiguration={"suffixPath": "post-delete-suffix", "enableHiveCompatiblePath": False},
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"UpdateDeliveryConfiguration on a deleted delivery should be rejected as not-found, got {mutate_code}"
    )
    expected = "Requested Delivery does not exist in this account."
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _create_bucket(ctx, prefix: str):
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix).lower().replace("_", "-")
    region = ctx.region
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: s3.delete_bucket(Bucket=name)))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
    )
    return name, f"arn:aws:s3:::{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
