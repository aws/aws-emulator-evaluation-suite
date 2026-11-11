"""delete-table-stale-version-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-table-stale-version-token-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        err = response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTable with a stale versionToken is ConflictException "Provided version token does not match
    the table version token." and leaves the table in place, while the delete with the current token
    succeeds (GetTable then answers NotFoundException)."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-vtoken-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-vtoken"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    ns_name = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns_name))

    table_name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=bucket_arn,
        namespace=ns_name,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-vtoken"},
    )
    real_token = created["versionToken"]

    def _cleanup_table():
        # The positive control below deletes the table itself; this is a safety net
        # in case an assertion fails earlier, so a NotFoundException here is fine.
        try:
            s3tables.delete_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is None or response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_table)

    # A stale token that is well-formed but does not match the table's current version.
    stale_token = ("0" if real_token[0] != "0" else "1") + real_token[1:]
    assert stale_token != real_token

    code, message = _error(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn,
            namespace=ns_name,
            name=table_name,
            versionToken=stale_token,
        )
    )
    assert code == "ConflictException", code
    assert message == "Provided version token does not match the table version token.", message

    # Effect absent: the table must still exist.
    still_there = s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    assert still_there["name"] == table_name

    # Positive control: deleting with the real, current versionToken succeeds.
    s3tables.delete_table(
        tableBucketARN=bucket_arn, namespace=ns_name, name=table_name, versionToken=real_token
    )
    code_after, message_after = _error(
        lambda: s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    )
    assert code_after == "NotFoundException", code_after
    assert message_after == "The specified table does not exist.", message_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
