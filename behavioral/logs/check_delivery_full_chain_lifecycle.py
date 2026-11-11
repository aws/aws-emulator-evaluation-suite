"""delivery-full-chain-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delivery-full-chain-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery links an existing source and destination into a delivery visible via
    GetDelivery/DescribeDeliveries, mutable via UpdateDeliveryConfiguration, and removable via
    DeleteDelivery."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-dlv-chain-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    source_name = ctx.unique_name("sim2real-chain-source-")
    logs.put_delivery_source(name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS")
    ctx.on_cleanup(lambda: _safe_delete_source(logs, source_name))

    # recordFields (the mutable knob exercised below via UpdateDeliveryConfiguration) is only
    # accepted for delivery destinations that emit a flat/delimited record format (e.g. S3);
    # a CloudWatch Logs (CWL) destination always delivers full JSON and rejects recordFields
    # customization outright ("Provided invalid record fields"), regardless of the field
    # names chosen. Use an S3 destination so the mutation is actually valid to exercise.
    dest_bucket_name = ctx.unique_name("sim2real-dlv-chain-dst-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=dest_bucket_name)
    else:
        s3.create_bucket(
            Bucket=dest_bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=dest_bucket_name))
    dest_bucket_arn = f"arn:aws:s3:::{dest_bucket_name}"

    destination_name = ctx.unique_name("sim2real-chain-destination-")
    dest_arn = logs.put_delivery_destination(
        name=destination_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_bucket_arn},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete_destination(logs, destination_name))

    create_resp = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn)
    delivery = create_resp["delivery"]
    delivery_id = delivery["id"]
    ctx.on_cleanup(lambda: _safe_delete_delivery(logs, delivery_id))
    assert delivery["deliverySourceName"] == source_name, delivery
    assert delivery["deliveryDestinationArn"] == dest_arn, delivery

    got = logs.get_delivery(id=delivery_id)["delivery"]
    assert got["id"] == delivery_id, got
    assert got["deliverySourceName"] == source_name, got

    described = logs.describe_deliveries()
    ids = [d["id"] for d in described.get("deliveries", [])]
    assert delivery_id in ids, f"{delivery_id} not in {ids}"

    # fieldDelimiter only applies to delivery destinations that emit delimited text (e.g. S3);
    # recordFields is the mutable knob being exercised here. The set of valid field names is
    # specific to the (service, logType, deliveryDestinationType) tuple, so discover it from
    # DescribeConfigurationTemplates rather than guessing names -- guessed names (e.g.
    # "bucket_owner") are rejected by AWS with "Provided invalid record fields".
    templates = logs.describe_configuration_templates(
        service="s3", logTypes=["S3_SERVER_ACCESS_LOGS"], deliveryDestinationTypes=["S3"]
    )["configurationTemplates"]
    assert templates, "no configuration template found for S3_SERVER_ACCESS_LOGS -> S3"
    allowed_field_entries = templates[0]["allowedFields"]
    allowed_fields = [f["name"] for f in allowed_field_entries]
    assert len(allowed_fields) >= 2, allowed_fields
    # UpdateDeliveryConfiguration rejects a recordFields set that omits any field flagged
    # "mandatory" in the configuration template (error: "Mandatory record fields are
    # missing"). Always include those, then round out to a few optional fields.
    mandatory_fields = [f["name"] for f in allowed_field_entries if f.get("mandatory")]
    optional_fields = [f["name"] for f in allowed_field_entries if not f.get("mandatory")]
    chosen_fields = mandatory_fields + optional_fields[: max(0, 3 - len(mandatory_fields))]
    if not chosen_fields:
        chosen_fields = allowed_fields[:3] if len(allowed_fields) >= 3 else allowed_fields

    logs.update_delivery_configuration(id=delivery_id, recordFields=chosen_fields)
    got_after = logs.get_delivery(id=delivery_id)["delivery"]
    assert set(got_after.get("recordFields") or []) == set(chosen_fields), got_after

    logs.delete_delivery(id=delivery_id)
    code, message = _expect_error(lambda: logs.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The dead delivery id must also reject a mutation, not just a read.
    code, message = _expect_error(
        lambda: logs.update_delivery_configuration(id=delivery_id, recordFields=chosen_fields)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Now unreferenced: source and destination should delete cleanly, and each becomes
    # independently unreadable -- not just absent from the delivery, but gone in its own right.
    logs.delete_delivery_source(name=source_name)
    code, message = _expect_error(lambda: logs.get_delivery_source(name=source_name))
    assert code == "ResourceNotFoundException", f"source: expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Source does not exist in this account."
    assert message == expected, f"source: expected message {expected!r}, got {message!r}"

    logs.delete_delivery_destination(name=destination_name)
    code, message = _expect_error(lambda: logs.get_delivery_destination(name=destination_name))
    assert code == "ResourceNotFoundException", f"destination: expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Destination does not exist in this account."
    assert message == expected, f"destination: expected message {expected!r}, got {message!r}"


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete_delivery(logs, delivery_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_delivery(id=delivery_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_source(logs, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_delivery_source(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_destination(logs, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_delivery_destination(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
