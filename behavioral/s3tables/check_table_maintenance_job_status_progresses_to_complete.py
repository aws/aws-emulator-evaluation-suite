"""table-maintenance-job-status-progresses-to-complete."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-maintenance-job-status-progresses-to-complete"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableMaintenanceJobStatus reports Not_Yet_Run for a new table, and after the maintenance type is
    disabled it reports Disabled within the poll deadline (a real maintenance run has no documented
    interval, so only the configuration-driven transition is asserted)."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, "maint")
    table = _create_table(ctx, bucket_arn, "maint")

    def probe() -> str:
        resp = s3tables.get_table_maintenance_job_status(
            tableBucketARN=bucket_arn, namespace=table["namespace"], name=table["name"]
        )
        return resp["status"]["icebergCompaction"]["status"]

    # Positive control: a brand-new table has never had compaction run.
    initial_status = probe()
    assert initial_status == "Not_Yet_Run", (
        f"expected a fresh table's icebergCompaction status to be Not_Yet_Run, got {initial_status!r}"
    )

    s3tables.put_table_maintenance_configuration(
        tableBucketARN=bucket_arn,
        namespace=table["namespace"],
        name=table["name"],
        type="icebergCompaction",
        value={"status": "disabled"},
    )

    final_status = _poll_until(
        probe,
        lambda status: status == "Disabled",
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert final_status == "Disabled", (
        f"expected icebergCompaction status Disabled after disabling maintenance, got {final_status!r}"
    )


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_table(ctx, bucket_arn: str, prefix: str) -> dict[str, str]:
    s3tables = ctx.client("s3tables")
    namespace = _sanitize(ctx.unique_name(f"sim2real_{prefix}_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        )
    )
    name = _sanitize(ctx.unique_name(f"sim2real_{prefix}_tbl_"))
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    table_arn = resp["tableARN"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
        )
    )
    return {"arn": table_arn, "namespace": namespace, "name": name}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
