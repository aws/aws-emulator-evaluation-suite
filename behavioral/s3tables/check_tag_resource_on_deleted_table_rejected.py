"""tag-resource-on-deleted-table-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "tag-resource-on-deleted-table-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging a table after it has been deleted must fail rather than silently
    succeed against a stale resource identity; a still-live sibling table
    (positive control) can still be tagged successfully."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    )

    deleted_table_name = ctx.unique_name("tbl_del_").replace("-", "_")
    deleted_table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace_name,
        name=deleted_table_name,
        format="ICEBERG",
    )["tableARN"]

    live_table_name = ctx.unique_name("tbl_live_").replace("-", "_")
    live_table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace_name,
        name=live_table_name,
        format="ICEBERG",
    )["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace_name, name=live_table_name
        )
    )

    s3tables.delete_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=deleted_table_name
    )

    # break: tag the now-deleted table's stale ARN
    code, message = _error_of(
        lambda: s3tables.tag_resource(
            resourceArn=deleted_table_arn, tags={"stale": "should-not-attach"}
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "The specified table does not exist.", message

    # positive control: tagging the still-live sibling table succeeds
    s3tables.tag_resource(resourceArn=live_table_arn, tags={"live": "attached"})
    got = s3tables.list_tags_for_resource(resourceArn=live_table_arn)["tags"]
    assert got["live"] == "attached", f"expected live tag attached, got {got}"


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-stale-tag-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _error_of(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
