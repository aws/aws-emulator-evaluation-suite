"""bucket-metadata-configuration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBucketMetadataConfiguration provisions the config, Get reflects it, Delete removes it."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-metacfg-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    ctx.on_cleanup(lambda: _safe(s3.delete_bucket_metadata_configuration, Bucket=bucket))

    metadata_cfg = {"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}}
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=metadata_cfg)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError("insufficient permissions to create S3 Metadata configuration") from exc
        raise

    got = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: "JournalTableConfigurationResult" in r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"],
        timeout_s=60,
        interval_s=3,
    )
    result = got["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    journal = result["JournalTableConfigurationResult"]
    assert journal["RecordExpiration"]["Expiration"] == "DISABLED", (
        f"expected journal table RecordExpiration to reflect the DISABLED value we set, got {journal['RecordExpiration']!r}"
    )
    assert journal.get("TableStatus") in ("CREATING", "ACTIVE", None), (
        f"expected journal table status to be CREATING, ACTIVE or absent shortly after creation, got {journal.get('TableStatus')!r}"
    )

    s3.delete_bucket_metadata_configuration(Bucket=bucket)

    # Deletion is asynchronous on real AWS: GetBucketMetadataConfiguration can keep
    # succeeding for a while after the delete call returns (reflecting a configuration that
    # no longer includes the journal table) before it eventually starts raising a
    # "no such configuration" style error. Accept either signal that the configuration is
    # gone, and give the async teardown a generous bounded window.
    deadline = time.monotonic() + 240
    code = None
    gone = False
    while time.monotonic() < deadline:
        try:
            resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidRequest", "NoSuchConfiguration", "MetadataConfigurationNotFound"):
                gone = True
                break
        else:
            code = None
            cfg = resp.get("GetBucketMetadataConfigurationResult", {}).get("MetadataConfigurationResult", {})
            if "JournalTableConfigurationResult" not in cfg:
                gone = True
                break
        time.sleep(5)
    assert gone, (
        f"expected metadata configuration to be absent after delete, got error code {code!r}"
    )


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result: {last!r}")


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
