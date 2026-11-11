"""create-delivery-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_missing(fn):
    """Teardown helper: run fn() and tolerate a ResourceNotFoundException (already deleted)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_source_bucket(ctx, tag):
    """Create a REAL, empty S3 bucket to use as a delivery-source resource.
    Returns the bucket name; registered for teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")[:63].rstrip("-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": CHECK}]})

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


CHECK = "create-delivery-lifecycle"
GROUP = 'delivery'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDelivery links a real source and destination into a delivery that Get/DescribeDeliveries
    return and UpdateDeliveryConfiguration changes; DeleteDelivery removes it (Get then 404s)
    without touching the underlying source or destination."""
    svc = ctx.client("logs")
    tagset = {"sim2real-behav": CHECK}
    bucket = _create_source_bucket(ctx, "dlv")
    source_name = ctx.unique_name("sim2real-behav-dlvsrc-")
    svc.put_delivery_source(
        name=source_name,
        resourceArn=f"arn:aws:s3:::{bucket}",
        logType="S3_SERVER_ACCESS_LOGS",
        tags=tagset,
    )
    ctx.on_cleanup(lambda _n=source_name: _ignore_missing(lambda: svc.delete_delivery_source(name=_n)))

    target_group = ctx.unique_name("sim2real-behav-lg-dlv-")
    svc.create_log_group(logGroupName=target_group, tags=tagset)
    ctx.on_cleanup(lambda _n=target_group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=target_group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    target_arn = svc.describe_log_groups(logGroupNamePrefix=target_group)["logGroups"][0]["logGroupArn"]

    dest_name = ctx.unique_name("sim2real-behav-dlvdst-")
    dest_resp = svc.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": target_arn},
        tags=tagset,
    )
    ctx.on_cleanup(lambda _n=dest_name: _ignore_missing(lambda: svc.delete_delivery_destination(name=_n)))
    dest_arn = dest_resp["deliveryDestination"]["arn"]

    create_resp = svc.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn, tags=tagset
    )
    delivery_id = create_resp["delivery"]["id"]
    ctx.on_cleanup(lambda _i=delivery_id: _ignore_missing(lambda: svc.delete_delivery(id=_i)))
    assert create_resp["delivery"]["deliverySourceName"] == source_name, create_resp["delivery"]
    assert create_resp["delivery"]["deliveryDestinationArn"] == dest_arn, create_resp["delivery"]

    got = svc.get_delivery(id=delivery_id)
    assert got["delivery"]["id"] == delivery_id, got["delivery"]
    assert got["delivery"]["deliveryDestinationArn"] == dest_arn, got["delivery"]

    listed = svc.describe_deliveries()
    ids = {d["id"] for d in listed.get("deliveries", [])}
    assert delivery_id in ids, f"delivery not listed via DescribeDeliveries: {ids!r}"

    # AWS rejects a recordFields name outside the template's allowedFields ("Provided invalid
    # record fields"), so pick an allowed field not in the default set to make a real change.
    base_fields = got["delivery"].get("recordFields", [])
    templates = svc.describe_configuration_templates(
        service="s3", logTypes=["S3_SERVER_ACCESS_LOGS"], deliveryDestinationTypes=["CWL"]
    )["configurationTemplates"]
    assert templates, "no configuration template found for S3_SERVER_ACCESS_LOGS -> CWL"
    allowed_field_entries = templates[0]["allowedFields"]
    mandatory_fields = [f["name"] for f in allowed_field_entries if f.get("mandatory")]
    optional_fields = [f["name"] for f in allowed_field_entries if not f.get("mandatory")]
    candidate_extra = next((f for f in optional_fields if f not in base_fields), None)
    new_fields = (
        base_fields + [candidate_extra] if candidate_extra else list(reversed(base_fields))
    )
    assert new_fields != base_fields, (
        f"configuration template offered no field to change: base={base_fields!r} "
        f"mandatory={mandatory_fields!r} optional={optional_fields!r}"
    )
    svc.update_delivery_configuration(id=delivery_id, recordFields=new_fields)
    updated = svc.get_delivery(id=delivery_id)
    assert updated["delivery"].get("recordFields") == new_fields, (
        f"recordFields update via UpdateDeliveryConfiguration not reflected: {updated['delivery']!r}"
    )

    svc.delete_delivery(id=delivery_id)
    code, msg = _error(lambda: svc.get_delivery(id=delivery_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "Requested Delivery does not exist in this account.", f"unexpected message: {msg!r}"

    code, msg = _error(
        lambda: svc.update_delivery_configuration(id=delivery_id, recordFields=base_fields)
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateDeliveryConfiguration on a deleted delivery should 404, got {code!r} {msg!r}"
    )
    assert msg == "Requested Delivery does not exist in this account.", f"unexpected message: {msg!r}"

    svc.delete_delivery_destination(name=dest_name)
    svc.delete_delivery_source(name=source_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
