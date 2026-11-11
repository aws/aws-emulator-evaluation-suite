"""bucket-inventory-configuration-roundtrip."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-inventory-configuration-roundtrip"
GROUP = 'inventory_config'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketInventoryConfiguration entries appear in list/get and disappear after delete."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cfg_id = "sim2real-inventory"
    config = {
        "Id": cfg_id,
        "IsEnabled": True,
        "IncludedObjectVersions": "Current",
        "Schedule": {"Frequency": "Daily"},
        "Destination": {
            "S3BucketDestination": {
                "AccountId": account_id,
                "Bucket": f"arn:aws:s3:::{bucket}",
                "Format": "CSV",
                "Prefix": "inventory-reports",
            }
        },
    }

    s3.put_bucket_inventory_configuration(Bucket=bucket, Id=cfg_id, InventoryConfiguration=config)
    fetched = s3.get_bucket_inventory_configuration(Bucket=bucket, Id=cfg_id)["InventoryConfiguration"]
    assert fetched["Id"] == cfg_id
    assert fetched["IsEnabled"] is True

    listed = s3.list_bucket_inventory_configurations(Bucket=bucket)
    ids = {c["Id"] for c in listed.get("InventoryConfigurationList", [])}
    assert cfg_id in ids, f"expected {cfg_id} in ListBucketInventoryConfigurations, got {ids}"

    s3.delete_bucket_inventory_configuration(Bucket=bucket, Id=cfg_id)
    code, message = _error(lambda: s3.get_bucket_inventory_configuration(Bucket=bucket, Id=cfg_id))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration after delete, got {code}"
    assert message == "The specified configuration does not exist.", message
    listed_after = s3.list_bucket_inventory_configurations(Bucket=bucket)
    ids_after = {c["Id"] for c in listed_after.get("InventoryConfigurationList", [])}
    assert cfg_id not in ids_after, "deleted inventory config must disappear from the list"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
