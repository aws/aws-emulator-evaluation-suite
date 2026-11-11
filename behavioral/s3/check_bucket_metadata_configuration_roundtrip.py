"""bucket-metadata-configuration-roundtrip."""

from __future__ import annotations
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-metadata-configuration-roundtrip"
GROUP = 'metadata_config'
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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy. Returns the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBucketMetadataConfiguration is retrievable and removable via
    DeleteBucketMetadataConfiguration."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    s3.create_bucket_metadata_configuration(
        Bucket=bucket,
        MetadataConfiguration={"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}},
    )

    def _get():
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        outer = resp.get("GetBucketMetadataConfigurationResult", resp)
        return outer.get("MetadataConfigurationResult", outer)

    fetched = _poll_until(
        _get,
        lambda r: r.get("JournalTableConfigurationResult", {}).get("TableStatus") == "ACTIVE",
        timeout_s=120,
        interval_s=5,
        description="journal table to become ACTIVE",
    )
    journal = fetched["JournalTableConfigurationResult"]
    assert journal["RecordExpiration"]["Expiration"] == "DISABLED", (
        f"expected the RecordExpiration set at create time to round-trip through Get, "
        f"got {journal.get('RecordExpiration')!r}"
    )

    s3.delete_bucket_metadata_configuration(Bucket=bucket)
    code, message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert code == "MetadataConfigurationNotFound", (
        f"expected MetadataConfigurationNotFound for GetBucketMetadataConfiguration after "
        f"delete, got {code!r}"
    )
    assert message == "The metadata configuration was not found", message


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the journal and inventory tables, and their namespace, that the bucket's metadata
    configuration leaves in the account's AWS-managed table bucket: deleting the configuration
    or the bucket keeps them, and they bill. Only an already-absent table or namespace is
    tolerated."""
    from botocore.exceptions import ClientError

    tables = ctx.client("s3tables")
    arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/aws-s3"
    namespace = f"b_{bucket}"
    try:
        for page in tables.get_paginator("list_tables").paginate(
            tableBucketARN=arn, namespace=namespace
        ):
            for table in page.get("tables", []):
                tables.delete_table(tableBucketARN=arn, namespace=namespace, name=table["name"])
        tables.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
