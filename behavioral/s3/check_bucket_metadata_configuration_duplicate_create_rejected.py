"""bucket-metadata-configuration-duplicate-create-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-metadata-configuration-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateBucketMetadataConfiguration on a bucket that already has one is rejected
    (state-conflict), leaving the original configuration intact."""
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-metadup-")
    _create_bucket(ctx, bucket)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))

    metadata_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
    }
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=metadata_config)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"insufficient permissions for S3 Metadata configuration: {code}")
        raise
    ctx.on_cleanup(
        lambda: _best_effort(lambda: s3.delete_bucket_metadata_configuration(Bucket=bucket))
    )

    code, message = _error(
        lambda: s3.create_bucket_metadata_configuration(
            Bucket=bucket, MetadataConfiguration=metadata_config
        )
    )
    assert code == "MetadataConfigurationAlreadyExists", (
        f"unexpected code for duplicate create: {code}"
    )
    assert message == "The metadata configuration already exists", message

    # original configuration must still be present/unaffected by the rejected duplicate
    got = s3.get_bucket_metadata_configuration(Bucket=bucket)
    assert "GetBucketMetadataConfigurationResult" in got
    meta_result = got["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    assert "JournalTableConfigurationResult" in meta_result

    # restore leg: the rejection is a state conflict, not a malformed request, so once the
    # existing configuration is removed the identical call must succeed again.
    s3.delete_bucket_metadata_configuration(Bucket=bucket)
    gone_code, gone_message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert gone_code == "MetadataConfigurationNotFound", (
        f"expected MetadataConfigurationNotFound after delete, got {gone_code}"
    )
    assert gone_message == "The metadata configuration was not found", gone_message

    s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=metadata_config)
    ctx.on_cleanup(
        lambda: _best_effort(lambda: s3.delete_bucket_metadata_configuration(Bucket=bucket))
    )
    restored = s3.get_bucket_metadata_configuration(Bucket=bucket)
    restored_result = restored["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    assert "JournalTableConfigurationResult" in restored_result, (
        "expected the identical create to succeed once the state conflict is cleared"
    )


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's region-pinned default: it rejects an explicit
        # LocationConstraint, so the param is only supplied for every other region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _cleanup_bucket(ctx, bucket))


def _cleanup_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("MetadataConfigurationNotFound", "NoSuchBucket"):
            raise


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
