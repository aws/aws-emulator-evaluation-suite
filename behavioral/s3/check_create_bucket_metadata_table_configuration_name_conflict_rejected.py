"""create-bucket-metadata-table-configuration-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bucket-metadata-table-configuration-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

_ALREADY_EXISTS = ("MetadataConfigurationAlreadyExists", "The metadata configuration already exists")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateBucketMetadataConfiguration on a bucket whose configuration is ACTIVE is
    rejected as MetadataConfigurationAlreadyExists rather than overwriting or duplicating the
    AWS-managed metadata tables; a re-create after delete fails on the leftover journal table."""
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-mtbc-")
    s3.create_bucket(Bucket=bucket, **_bucket_location_kwargs(s3))
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_journal_namespace(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_metadata_configuration(ctx, bucket))

    journal_cfg = {"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}}

    s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=journal_cfg)
    status = _poll_journal_status(ctx, bucket, timeout_s=180.0)
    assert status == "ACTIVE", f"expected first configuration ACTIVE, got {status}"

    # Creating a SECOND configuration on the SAME bucket while the first is still
    # active must be rejected as a conflict, not silently accepted/duplicated.
    conflict = _error(
        lambda: s3.create_bucket_metadata_configuration(
            Bucket=bucket, MetadataConfiguration=journal_cfg
        )
    )
    assert conflict == _ALREADY_EXISTS, f"expected {_ALREADY_EXISTS!r}, got {conflict!r}"

    # effect unchanged: the original configuration is still exactly the one in place
    still = s3.get_bucket_metadata_configuration(Bucket=bucket)
    still_status = still["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"
    ]["TableStatus"]
    assert still_status == "ACTIVE", f"expected original configuration still ACTIVE, got {still_status}"

    # restore, and a deeper real invariant with it: deleting the metadata
    # CONFIGURATION does not delete the journal TABLE it provisioned in the
    # AWS-managed table bucket namespace. The identical create is accepted
    # synchronously (unlike the first conflict above, which botocore raises
    # immediately), but the async provisioning it kicks off still conflicts with
    # that leftover table and lands in FAILED with a table-scoped error -- distinct
    # from the configuration-scoped MetadataConfigurationAlreadyExists asserted
    # above. A target that treated "delete the configuration" as freeing the name
    # for immediate reuse would diverge from real AWS right here.
    _delete_metadata_configuration(ctx, bucket)
    s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=journal_cfg)
    restored_status, restored_error = _poll_journal_status_detail(ctx, bucket, timeout_s=180.0)
    assert restored_status == "FAILED", (
        f"expected the identical create to still conflict on the leftover journal "
        f"table, got status={restored_status} error={restored_error}"
    )
    want_error = {
        "ErrorCode": "JournalTableAlreadyExists",
        "ErrorMessage": (
            "A journal table already exists in the AWS managed table bucket's namespace. "
            "Delete the journal table, and then try again. To create a new S3 Metadata "
            "table, you must delete the S3 Metadata configuration for this bucket, and "
            "then create a new S3 Metadata configuration."
        ),
    }
    assert restored_error == want_error, (
        f"expected {want_error!r} on the leftover journal table, got {restored_error!r}"
    )

    # positive control: a metadata configuration on a fresh, unrelated bucket succeeds
    control_bucket = ctx.unique_name("sim2real-mtbc-ctrl-")
    s3.create_bucket(Bucket=control_bucket, **_bucket_location_kwargs(s3))
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=control_bucket))
    ctx.on_cleanup(lambda: _delete_journal_namespace(ctx, control_bucket))
    s3.create_bucket_metadata_configuration(Bucket=control_bucket, MetadataConfiguration=journal_cfg)
    ctx.on_cleanup(lambda: _delete_metadata_configuration(ctx, control_bucket))
    control_status = _poll_journal_status(ctx, control_bucket, timeout_s=180.0)
    assert control_status == "ACTIVE", f"expected control configuration ACTIVE, got {control_status}"


def _bucket_location_kwargs(s3):
    region = s3.meta.region_name
    if region and region != "us-east-1":
        return {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return {}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check, so an over-permissive target is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_journal_status(ctx, bucket: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        result = resp["GetBucketMetadataConfigurationResult"]
        status = result["MetadataConfigurationResult"]["JournalTableConfigurationResult"]["TableStatus"]
        if status in ("ACTIVE", "FAILED"):
            return status
        time.sleep(interval_s)
    return status


def _poll_journal_status_detail(ctx, bucket: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    status = None
    error = None
    while time.monotonic() < deadline:
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        result = resp["GetBucketMetadataConfigurationResult"]
        journal = result["MetadataConfigurationResult"]["JournalTableConfigurationResult"]
        status = journal.get("TableStatus")
        error = journal.get("Error")
        if status in ("ACTIVE", "FAILED"):
            return status, error
        time.sleep(interval_s)
    return status, error


def _delete_metadata_configuration(ctx, bucket: str) -> None:
    """Delete the bucket's metadata configuration; absent is done, a 409 conflict is retried."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + 60
    while True:
        try:
            s3.delete_bucket_metadata_configuration(Bucket=bucket)
            return
        except ClientError as exc:
            status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
            if exc.response["Error"]["Code"] in ("MetadataConfigurationNotFound", "NoSuchBucket") or status == 404:
                return
            if status != 409 or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_journal_namespace(ctx, bucket: str) -> None:
    """Delete the journal table and namespace a metadata configuration leaves in the
    AWS-managed table bucket; deleting the configuration alone keeps them."""
    tables = ctx.client("s3tables")
    arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/aws-s3"
    namespace = f"b_{bucket}"
    try:
        for page in tables.get_paginator("list_tables").paginate(tableBucketARN=arn, namespace=namespace):
            for table in page.get("tables", []):
                tables.delete_table(tableBucketARN=arn, namespace=namespace, name=table["name"])
        tables.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
