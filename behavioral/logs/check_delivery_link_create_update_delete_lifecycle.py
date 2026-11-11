"""delivery-link-create-update-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delivery-link-create-update-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery links a source+destination; visible via Get/Describe; mutable via
    UpdateDeliveryConfiguration; removable via DeleteDelivery (subsequent Get 404s)."""
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
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["deliveryDestination"]
    dest_arn = dest["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery_destination(name=dest_name)))

    created = logs.create_delivery(
        deliverySourceName=source_name,
        deliveryDestinationArn=dest_arn,
        tags={"Sim2RealOwner": "behavioral-suite"},
    )["delivery"]
    assert created["deliverySourceName"] == source_name
    assert created["deliveryDestinationArn"] == dest_arn
    delivery_id = created["id"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_delivery(id=delivery_id)))

    got = logs.get_delivery(id=delivery_id)["delivery"]
    assert got["id"] == delivery_id
    assert got["deliverySourceName"] == source_name
    assert got["deliveryDestinationArn"] == dest_arn

    described = logs.describe_deliveries()["deliveries"]
    assert any(d["id"] == delivery_id for d in described)

    # Mutate the delivery configuration. fieldDelimiter only applies when the destination's
    # output format is Plain/W3C/Raw; this delivery's destination is a CloudWatch Logs log
    # group, which uses the JSON output format, so fieldDelimiter is rejected there. Mutate
    # recordFields instead (applicable regardless of output format) by reordering the fields
    # that were assigned by default when the delivery was created.
    default_fields = created.get("recordFields") or got.get("recordFields")
    assert default_fields, "expected the delivery to have default recordFields assigned"
    new_fields = list(reversed(default_fields))
    logs.update_delivery_configuration(id=delivery_id, recordFields=new_fields)
    updated = logs.get_delivery(id=delivery_id)["delivery"]
    assert updated["recordFields"] == new_fields

    logs.delete_delivery(id=delivery_id)

    code, message = _expect_error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described_after = logs.describe_deliveries()["deliveries"]
    assert not any(d["id"] == delivery_id for d in described_after)

    # A mutation on the now-dead id must fail the same way a read does -- otherwise
    # UpdateDeliveryConfiguration would be operating on a delivery that no longer exists.
    mutate_code, mutate_message = _expect_error(
        lambda: logs.update_delivery_configuration(id=delivery_id, recordFields=default_fields)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateDeliveryConfiguration on a deleted delivery to 404, got {mutate_code}"
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


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-dlink-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=name)))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
    )
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
