"""update-table-metadata-location-stale-token-leaves-location-and-token-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-metadata-location-stale-token-leaves-location-and-token-unchanged"
GROUP = "metadata"
SERVICES = ["s3tables"]

_NAMESPACE = "analytics"
_CONFLICT = (
    "ConflictException",
    "Provided version token does not match the table version token.",
)


def _error(fn):
    """Call fn() expecting a refusal; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTableMetadataLocation with a stale version token is refused, and both the
    location and the token GetTableMetadataLocation returns stay at the prior, successful
    values; the same call with the current token then advances both on the same table.
    """
    s3t = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-")
    bucket_arn = s3t.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(
        _teardown(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn), "NotFoundException")
    )

    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[_NAMESPACE])
    ctx.on_cleanup(
        _teardown(
            lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=_NAMESPACE),
            "NotFoundException",
        )
    )

    table_name = ctx.unique_name("sim2real_behav_")
    created = s3t.create_table(
        tableBucketARN=bucket_arn, namespace=_NAMESPACE, name=table_name, format="ICEBERG"
    )
    ctx.on_cleanup(
        _teardown(
            lambda: s3t.delete_table(
                tableBucketARN=bucket_arn, namespace=_NAMESPACE, name=table_name
            ),
            "NotFoundException",
        )
    )
    original_token = created["versionToken"]

    warehouse = s3t.get_table(
        tableBucketARN=bucket_arn, namespace=_NAMESPACE, name=table_name
    )["warehouseLocation"].rstrip("/")

    first_location = f"{warehouse}/metadata/00001-first.metadata.json"
    first_update = s3t.update_table_metadata_location(
        tableBucketARN=bucket_arn,
        namespace=_NAMESPACE,
        name=table_name,
        metadataLocation=first_location,
        versionToken=original_token,
    )
    first_token = first_update["versionToken"]
    assert first_token != original_token, (
        f"the accepted update returned the same token {first_token!r} it was given"
    )

    second_location = f"{warehouse}/metadata/00002-second.metadata.json"
    code, message = _error(
        lambda: s3t.update_table_metadata_location(
            tableBucketARN=bucket_arn,
            namespace=_NAMESPACE,
            name=table_name,
            metadataLocation=second_location,
            versionToken=original_token,
        )
    )
    assert (code, message) == _CONFLICT, (code, message)

    after_refusal = s3t.get_table_metadata_location(
        tableBucketARN=bucket_arn, namespace=_NAMESPACE, name=table_name
    )
    assert after_refusal["metadataLocation"] == first_location, (
        f"metadataLocation after the refused update is "
        f"{after_refusal['metadataLocation']!r}, expected it to stay at {first_location!r}"
    )
    assert after_refusal["versionToken"] == first_token, (
        f"versionToken after the refused update is {after_refusal['versionToken']!r}, "
        f"expected it to stay at {first_token!r}"
    )

    second_update = s3t.update_table_metadata_location(
        tableBucketARN=bucket_arn,
        namespace=_NAMESPACE,
        name=table_name,
        metadataLocation=second_location,
        versionToken=first_token,
    )
    second_token = second_update["versionToken"]
    assert second_token != first_token, (
        f"the legal update with the current token returned the same token {second_token!r}"
    )

    final = s3t.get_table_metadata_location(
        tableBucketARN=bucket_arn, namespace=_NAMESPACE, name=table_name
    )
    assert final["metadataLocation"] == second_location, final
    assert final["versionToken"] == second_token, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
