"""create-table-invalid-format-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-invalid-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with a format outside the OpenTableFormat enum is BadRequestException "The specified
    open table format is not valid" and creates no table (GetTable is NotFoundException), while the
    same name with format ICEBERG succeeds."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)
    namespace = _create_namespace(ctx, s3tables, bucket_arn)
    table_name = _ident_name(ctx, "sim2real_tbl_")

    code, message = _error(
        lambda: s3tables.create_table(
            tableBucketARN=bucket_arn,
            namespace=namespace,
            name=table_name,
            format="PARQUET",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "The specified open table format is not valid", message

    not_created, not_created_message = _error(
        lambda: s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    )
    assert not_created == "NotFoundException", (
        f"table with invalid format appears to have been created: {not_created}"
    )
    assert not_created_message == "The specified table does not exist.", not_created_message

    # Positive control: the same name with the only valid format succeeds.
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name, format="ICEBERG"
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace, name=table_name
        )
    )
    assert resp["tableARN"], "create_table with valid format did not return a tableARN"

    # Terminal assertion is an independent read (GetTable), not the mutating call's own response.
    created = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert created["tableARN"] == resp["tableARN"], (
        f"independent read shows different tableARN: {created['tableARN']} != {resp['tableARN']}"
    )
    assert created["format"] == "ICEBERG", f"expected ICEBERG format, got {created['format']}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _ident_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    return re.sub(r"[^0-9a-z_]", "_", raw)[:255]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, s3tables, bucket_arn: str) -> str:
    ns = _ident_name(ctx, "sim2real_ns_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))
    return ns


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
