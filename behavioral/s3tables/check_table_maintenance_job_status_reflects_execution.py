"""table-maintenance-job-status-reflects-execution."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "table-maintenance-job-status-reflects-execution"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableMaintenanceJobStatus reports Not_Yet_Run for icebergCompaction on a new table, and after
    PutTableMaintenanceConfiguration writes 'disabled' it reports 'Disabled': a status derived by the
    service, not an echo of the written value."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    _create_namespace(ctx, bucket_arn, "ns")
    _create_table(ctx, bucket_arn, "ns", "tbl")

    initial = s3t.get_table_maintenance_job_status(
        tableBucketARN=bucket_arn, namespace="ns", name="tbl"
    )
    initial_status = initial["status"]["icebergCompaction"]["status"]
    assert initial_status == "Not_Yet_Run", (
        f"expected a freshly created table's job status to be Not_Yet_Run, got {initial_status!r}"
    )

    s3t.put_table_maintenance_configuration(
        tableBucketARN=bucket_arn,
        namespace="ns",
        name="tbl",
        type="icebergCompaction",
        value={"status": "disabled"},
    )

    cfg = s3t.get_table_maintenance_configuration(
        tableBucketARN=bucket_arn, namespace="ns", name="tbl"
    )
    written_status = cfg["configuration"]["icebergCompaction"]["status"]
    assert written_status == "disabled", (
        f"expected the config object to echo the lowercase value written, got {written_status!r}"
    )

    final = _poll_until(
        probe=lambda: s3t.get_table_maintenance_job_status(
            tableBucketARN=bucket_arn, namespace="ns", name="tbl"
        ),
        predicate=lambda resp: resp["status"]["icebergCompaction"]["status"] == "Disabled",
        timeout_s=60.0,
        interval_s=3.0,
    )
    final_status = final["status"]["icebergCompaction"]["status"]
    assert final_status == "Disabled", (
        f"expected the job status to derive a capitalized 'Disabled' distinct from the "
        f"lowercase config value {written_status!r}, got {final_status!r}"
    )
    assert final_status != written_status, (
        "job status must be a derived, server-computed lifecycle state, not a case-preserving "
        "echo of the config value written"
    )


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn: str, ns: str) -> None:
    s3t = ctx.client("s3tables")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))


def _create_table(ctx, bucket_arn: str, ns: str, name: str) -> str:
    s3t = ctx.client("s3tables")
    arn = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=ns,
        name=name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["tableARN"]
    ctx.on_cleanup(lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=ns, name=name))
    return arn


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
