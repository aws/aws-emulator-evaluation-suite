"""delete-namespace-with-tables-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-namespace-with-tables-rejected"
GROUP = "e2e"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace on a namespace that still holds a table is BadRequestException "The namespace that
    you tried to delete is not empty." and leaves the namespace and table intact, and once the table is
    deleted the namespace delete succeeds (GetNamespace then answers NotFoundException)."""
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-s3t-nsdel-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    namespace_name = _sanitize(ctx.unique_name("sim2real_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: _swallow_not_found(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name))
    )

    table_name = _sanitize(ctx.unique_name("sim2real_tbl_"))
    s3tables.create_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG")
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
        )
    )

    # Break exactly one thing: try to delete a namespace that still has a table in it.
    code, message = _error(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "The namespace that you tried to delete is not empty.", message

    # Effect absent: both the namespace and the table it holds are still there.
    ns = s3tables.get_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    assert ns["namespace"] == [namespace_name], f"expected namespace {[namespace_name]!r}, got {ns['namespace']!r}"
    table = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    assert table["name"] == table_name, f"expected table {table_name!r} to still exist, got {table['name']!r}"

    # Positive control: removing the table first lets the same DeleteNamespace call succeed.
    s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    after_code, after_message = _error(lambda: s3tables.get_namespace(tableBucketARN=bucket_arn, namespace=namespace_name))
    assert after_code == "NotFoundException", (
        f"expected NotFoundException after the namespace was emptied and deleted, got {after_code!r}"
    )
    assert after_message == "The specified namespace does not exist.", after_message


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _swallow_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
