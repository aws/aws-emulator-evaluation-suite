"""delivery-source-and-destination-lifecycle."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delivery-source-and-destination-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource/PutDeliveryDestination create resources visible via their
    Get/Describe calls and removable when unreferenced."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-dlv-src-bkt-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted entirely;
    # every other region requires an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    source_name = ctx.unique_name("sim2real-delivery-source-")
    src_resp = logs.put_delivery_source(
        name=source_name,
        resourceArn=bucket_arn,
        logType="S3_SERVER_ACCESS_LOGS",
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe_delete_source(logs, source_name))
    assert src_resp["deliverySource"]["name"] == source_name, (
        f"expected deliverySource.name == {source_name!r}, got {src_resp['deliverySource'].get('name')!r}"
    )
    src_resource_arns = src_resp["deliverySource"]["resourceArns"]
    assert src_resource_arns == [bucket_arn] or bucket_arn in src_resource_arns, (
        f"expected {bucket_arn!r} in deliverySource.resourceArns, got {src_resource_arns!r}"
    )

    got_source = logs.get_delivery_source(name=source_name)["deliverySource"]
    assert got_source["logType"] == "S3_SERVER_ACCESS_LOGS", (
        f"expected logType == S3_SERVER_ACCESS_LOGS, got {got_source.get('logType')!r}"
    )

    described_sources = logs.describe_delivery_sources()
    source_names = [s["name"] for s in described_sources.get("deliverySources", [])]
    assert source_name in source_names, f"{source_name} not in {source_names}"

    dest_group_name = ctx.unique_name("sim2real-dlv-dest-lg-")
    logs.create_log_group(logGroupName=dest_group_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=dest_group_name))
    dest_group_arn = logs.describe_log_groups(logGroupNamePrefix=dest_group_name)["logGroups"][0]["arn"]

    destination_name = ctx.unique_name("sim2real-delivery-destination-")
    dest_resp = logs.put_delivery_destination(
        name=destination_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_group_arn},
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe_delete_destination(logs, destination_name))
    assert dest_resp["deliveryDestination"]["name"] == destination_name, (
        f"expected deliveryDestination.name == {destination_name!r}, "
        f"got {dest_resp['deliveryDestination'].get('name')!r}"
    )
    assert dest_resp["deliveryDestination"]["deliveryDestinationType"] == "CWL", (
        f"expected deliveryDestinationType == CWL, got {dest_resp['deliveryDestination'].get('deliveryDestinationType')!r}"
    )

    got_dest = logs.get_delivery_destination(name=destination_name)["deliveryDestination"]
    assert got_dest["deliveryDestinationConfiguration"]["destinationResourceArn"] == dest_group_arn, (
        f"expected destinationResourceArn == {dest_group_arn!r}, "
        f"got {got_dest['deliveryDestinationConfiguration'].get('destinationResourceArn')!r}"
    )

    described_dests = logs.describe_delivery_destinations()
    dest_names = [d["name"] for d in described_dests.get("deliveryDestinations", [])]
    assert destination_name in dest_names, f"{destination_name} not in {dest_names}"

    # Neither resource is referenced by an active delivery, so both should delete cleanly.
    logs.delete_delivery_source(name=source_name)
    code, message = _expect_error(lambda: logs.get_delivery_source(name=source_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Source does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    source_names_after = [s["name"] for s in logs.describe_delivery_sources().get("deliverySources", [])]
    assert source_name not in source_names_after, (
        f"{source_name} still listed by DescribeDeliverySources after DeleteDeliverySource: {source_names_after}"
    )

    logs.delete_delivery_destination(name=destination_name)
    code, message = _expect_error(lambda: logs.get_delivery_destination(name=destination_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Destination does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    dest_names_after = [
        d["name"] for d in logs.describe_delivery_destinations().get("deliveryDestinations", [])
    ]
    assert destination_name not in dest_names_after, (
        f"{destination_name} still listed by DescribeDeliveryDestinations after "
        f"DeleteDeliveryDestination: {dest_names_after}"
    )


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
