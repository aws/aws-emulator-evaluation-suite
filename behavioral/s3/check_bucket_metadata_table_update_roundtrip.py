"""bucket-metadata-table-update-roundtrip."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-metadata-table-update-roundtrip"
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
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every other
    # region requires one naming itself. Not a pin to a fixed home region.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


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


def _retry_until_success(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry fn() through ClientError (e.g. AccessDenied while a fresh IAM role's trust policy
    propagates) within a bounded window; re-raises the last error if it never succeeds."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation kept failing for {timeout_s}s: {last_exc}") from last_exc


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Metadata table sub-configurations (annotation/inventory/journal) can be updated in place
    after creation."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    s3.create_bucket_metadata_configuration(
        Bucket=bucket,
        MetadataConfiguration={
            "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}},
            "InventoryTableConfiguration": {"ConfigurationState": "DISABLED"},
        },
    )

    def _get():
        resp = s3.get_bucket_metadata_configuration(Bucket=bucket)
        outer = resp.get("GetBucketMetadataConfigurationResult", resp)
        return outer.get("MetadataConfigurationResult", outer)

    _poll_until(
        _get,
        lambda r: r.get("JournalTableConfigurationResult", {}).get("TableStatus") == "ACTIVE",
        timeout_s=120,
        interval_s=5,
        description="journal table to become ACTIVE before updating sub-configs",
    )

    # Journal: flip on record expiration in place.
    s3.update_bucket_metadata_journal_table_configuration(
        Bucket=bucket, JournalTableConfiguration={"RecordExpiration": {"Expiration": "ENABLED", "Days": 7}}
    )
    updated_journal = _get()["JournalTableConfigurationResult"]["RecordExpiration"]
    assert updated_journal["Expiration"] == "ENABLED", updated_journal
    assert updated_journal["Days"] == 7, updated_journal

    # Inventory: enable the live inventory table in place.
    s3.update_bucket_metadata_inventory_table_configuration(
        Bucket=bucket, InventoryTableConfiguration={"ConfigurationState": "ENABLED"}
    )
    _poll_until(
        lambda: _get().get("InventoryTableConfigurationResult", {}).get("ConfigurationState"),
        lambda s: s == "ENABLED",
        timeout_s=60,
        interval_s=5,
        description="inventory table ConfigurationState to flip to ENABLED",
    )

    # Annotation: flip it ENABLED in place. A target that quietly no-ops this update is
    # indistinguishable from a working one unless the state actually changes, so this needs a
    # real transition rather than DISABLED -> DISABLED — which means provisioning the IAM role
    # S3 requires (real AWS rejects ENABLED with InvalidRequest if Role is absent).
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-s3meta-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "metadata.s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]

    def _delete_role():
        # The inline policy must go before the role, or IAM refuses the role delete with
        # DeleteConflict -- do both in one cleanup so ctx's LIFO ordering can't split them.
        _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="read-annotations"))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="read-annotations",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )

    def _enable_annotation():
        s3.update_bucket_metadata_annotation_table_configuration(
            Bucket=bucket,
            AnnotationTableConfiguration={"ConfigurationState": "ENABLED", "Role": role_arn},
        )

    # The role's trust policy is eventually consistent from S3's point of view -- retry
    # through AccessDenied for a bounded window rather than assuming it's immediately assumable.
    _retry_until_success(_enable_annotation, timeout_s=90, interval_s=5)

    annotation = _poll_until(
        lambda: _get().get("AnnotationTableConfigurationResult", {}),
        lambda a: a.get("ConfigurationState") == "ENABLED",
        timeout_s=60,
        interval_s=5,
        description="annotation table ConfigurationState to flip to ENABLED",
    )
    assert annotation["ConfigurationState"] == "ENABLED", annotation
    assert annotation["Role"] == role_arn, annotation

    s3.delete_bucket_metadata_configuration(Bucket=bucket)
    code, message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert code == "MetadataConfigurationNotFound", code
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
