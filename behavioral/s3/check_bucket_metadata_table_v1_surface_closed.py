"""bucket-metadata-table-v1-surface-closed."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-table-v1-surface-closed"
GROUP = "legacy-surface-closure"
SERVICES = ["s3"]


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-metatblv1-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """(Code, Message) a ClientError carries; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The V1 CreateBucketMetadataTableConfiguration/Get/Delete trio is refused on a bucket that
    never had a V1 configuration, while the V2 GetBucketMetadataConfiguration on the same, still
    unconfigured bucket answers the ordinary MetadataConfigurationNotFound."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Control: the V2 surface is live and answers its documented not-configured error.
    v2_code, v2_message = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert v2_code == "MetadataConfigurationNotFound", (
        f"GetBucketMetadataConfiguration on an unconfigured bucket returned {v2_code!r}, "
        "expected MetadataConfigurationNotFound"
    )

    def _closure_message(v1_op: str, v2_op: str) -> str:
        return (
            f"The V1 {v1_op} API operation isn't available for this account. Use the "
            f"corresponding V2 {v2_op} API operation instead."
        )

    get_code, get_message = _error(lambda: s3.get_bucket_metadata_table_configuration(Bucket=bucket))
    assert get_code == "V1APIsNotAllowed", (
        f"GetBucketMetadataTableConfiguration on an account where the V1 surface is closed "
        f"answered {get_code!r}, expected V1APIsNotAllowed"
    )
    assert get_code != v2_code, (
        f"GetBucketMetadataTableConfiguration answered the same code as the V2 Get "
        f"({get_code!r}); the V1 surface should be closed, not merely unconfigured"
    )
    assert get_message == _closure_message(
        "GetBucketMetadataTableConfiguration", "GetBucketMetadataConfiguration"
    ), f"unexpected message for the closed V1 Get: {get_message!r}"

    delete_code, delete_message = _error(
        lambda: s3.delete_bucket_metadata_table_configuration(Bucket=bucket)
    )
    assert delete_code == get_code, (
        f"DeleteBucketMetadataTableConfiguration answered {delete_code!r}, expected the same "
        f"closure code as Get ({get_code!r})"
    )
    assert delete_message == _closure_message(
        "DeleteBucketMetadataTableConfiguration", "DeleteBucketMetadataConfiguration"
    ), f"unexpected message for the closed V1 Delete: {delete_message!r}"

    table_arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/sim2real-metatblv1-dest"
    create_code, create_message = _error(
        lambda: s3.create_bucket_metadata_table_configuration(
            Bucket=bucket,
            MetadataTableConfiguration={
                "S3TablesDestination": {"TableBucketArn": table_arn, "TableName": "sim2real_metadata"}
            },
        )
    )
    assert create_code == get_code, (
        f"CreateBucketMetadataTableConfiguration answered {create_code!r}, expected the same "
        f"closure code as Get and Delete ({get_code!r})"
    )
    assert create_message == _closure_message(
        "CreateBucketMetadataTableConfiguration", "CreateBucketMetadataConfiguration"
    ), f"unexpected message for the closed V1 Create: {create_message!r}"

    # Restore/positive control, repeated: the V2 surface is still unaffected by the three V1 calls.
    after_code, _ = _error(lambda: s3.get_bucket_metadata_configuration(Bucket=bucket))
    assert after_code == "MetadataConfigurationNotFound", (
        f"GetBucketMetadataConfiguration after the V1 refusals returned {after_code!r}, "
        "expected MetadataConfigurationNotFound, unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
