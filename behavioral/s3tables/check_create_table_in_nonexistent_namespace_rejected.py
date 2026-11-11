"""create-table-in-nonexistent-namespace-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-in-nonexistent-namespace-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable in a namespace that was never created is rejected with NotFoundException and leaves
    no table, while the same CreateTable succeeds once the namespace exists."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    missing_ns = ctx.unique_name("ns_missing_").replace("-", "_")
    table_name = ctx.unique_name("tbl_").replace("-", "_")

    code, message = _error(
        lambda: s3t.create_table(
            tableBucketARN=bucket_arn, namespace=missing_ns, name=table_name, format="ICEBERG"
        )
    )
    assert code == "NotFoundException", (
        f"CreateTable against a namespace that was never created must be rejected with "
        f"NotFoundException; got {code!r}"
    )
    assert message == "The specified namespace does not exist.", message

    # Effect absent: no table was created anywhere in the bucket by the rejected call.
    tables = s3t.list_tables(tableBucketARN=bucket_arn)["tables"]
    assert tables == [], f"the rejected CreateTable must leave no table behind; got {tables!r}"

    # Positive control: once the parent namespace actually exists, the same create succeeds.
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[missing_ns])
    ctx.on_cleanup(
        lambda: _safe(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=missing_ns))
    )
    resp = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=missing_ns,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=missing_ns, name=table_name)
        )
    )
    # tableARN embeds a system-generated table id, not the table name, so assert on the
    # documented bucket-scoped prefix and confirm the table is actually reachable by name.
    assert resp["tableARN"].startswith(f"{bucket_arn}/table/"), (
        f"tableARN must be scoped under the bucket's /table/ prefix; got {resp['tableARN']!r}"
    )
    described = s3t.get_table(tableBucketARN=bucket_arn, namespace=missing_ns, name=table_name)
    assert described["name"] == table_name, (
        f"GetTable must reach the table created once the namespace existed; got {described['name']!r}"
    )


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(
                name=name,
                tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
            )["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))
    ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
