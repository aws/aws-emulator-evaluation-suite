"""delivery-source-destination-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_if_present(fn):
    """Teardown for a resource the check itself deletes: an already-gone resource is fine."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_source_bucket(ctx, tag):
    """Create a REAL, empty S3 bucket to use as a delivery-source resource.
    Returns the bucket name; registered for teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")[:63].rstrip("-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region where CreateBucketConfiguration is rejected outright.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _teardown_bucket(_b=name, _s3=s3):
        try:
            for o in _s3.list_objects_v2(Bucket=_b).get("Contents", []):
                _s3.delete_object(Bucket=_b, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        _s3.delete_bucket(Bucket=_b)

    ctx.on_cleanup(_teardown_bucket)
    return name


CHECK = "delivery-source-destination-lifecycle"
GROUP = 'delivery'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource (S3 bucket) and PutDeliveryDestination (log group) are visible via
    Get/Describe, and their Delete operations remove them, leaving both Gets 404ing."""
    svc = ctx.client("logs")
    bucket = _create_source_bucket(ctx, "dlvsrc")
    source_name = ctx.unique_name("sim2real-behav-dlvsrc-")
    src_resp = svc.put_delivery_source(
        name=source_name,
        resourceArn=f"arn:aws:s3:::{bucket}",
        logType="S3_SERVER_ACCESS_LOGS",
    )
    ctx.on_cleanup(lambda _n=source_name: _delete_if_present(lambda: svc.delete_delivery_source(name=_n)))
    assert src_resp["deliverySource"]["logType"] == "S3_SERVER_ACCESS_LOGS"

    got_src = svc.get_delivery_source(name=source_name)
    assert got_src["deliverySource"]["name"] == source_name
    assert got_src["deliverySource"]["logType"] == "S3_SERVER_ACCESS_LOGS"

    listed_src = svc.describe_delivery_sources()
    src_names = {s["name"] for s in listed_src.get("deliverySources", [])}
    assert source_name in src_names, f"source not listed via DescribeDeliverySources: {src_names!r}"

    target_group = ctx.unique_name("sim2real-behav-lg-dlvdst-")
    svc.create_log_group(logGroupName=target_group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda _n=target_group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=target_group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    target_arn = svc.describe_log_groups(logGroupNamePrefix=target_group)["logGroups"][0]["logGroupArn"]

    dest_name = ctx.unique_name("sim2real-behav-dlvdst-")
    dest_resp = svc.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": target_arn},
    )
    ctx.on_cleanup(lambda _n=dest_name: _delete_if_present(lambda: svc.delete_delivery_destination(name=_n)))
    assert dest_resp["deliveryDestination"]["deliveryDestinationType"] == "CWL"

    got_dst = svc.get_delivery_destination(name=dest_name)
    assert got_dst["deliveryDestination"]["name"] == dest_name

    listed_dst = svc.describe_delivery_destinations()
    dst_names = {d["name"] for d in listed_dst.get("deliveryDestinations", [])}
    assert dest_name in dst_names, f"destination not listed via DescribeDeliveryDestinations: {dst_names!r}"

    svc.delete_delivery_destination(name=dest_name)
    dst_code, dst_message = _expect_error(lambda: svc.get_delivery_destination(name=dest_name))
    assert dst_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {dst_code!r}"
    expected = "Requested Delivery Destination does not exist in this account."
    assert dst_message == expected, f"expected message {expected!r}, got {dst_message!r}"
    dst_names_after = {d["name"] for d in svc.describe_delivery_destinations().get("deliveryDestinations", [])}
    assert dest_name not in dst_names_after, f"deleted destination still listed: {dst_names_after!r}"

    svc.delete_delivery_source(name=source_name)
    src_code, src_message = _expect_error(lambda: svc.get_delivery_source(name=source_name))
    assert src_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {src_code!r}"
    expected = "Requested Delivery Source does not exist in this account."
    assert src_message == expected, f"expected message {expected!r}, got {src_message!r}"
    src_names_after = {s["name"] for s in svc.describe_delivery_sources().get("deliverySources", [])}
    assert source_name not in src_names_after, f"deleted source still listed: {src_names_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
