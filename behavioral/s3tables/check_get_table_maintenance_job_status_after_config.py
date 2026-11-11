"""get-table-maintenance-job-status-after-config."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-table-maintenance-job-status-after-config"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After PutTableMaintenanceConfiguration disables icebergCompaction, the configuration reports status
    'disabled' while GetTableMaintenanceJobStatus reports 'Disabled' with no 'settings' field, both for
    the table's ARN: the job status is a separate view from the configuration."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    namespace = _create_namespace(ctx, bucket_arn)
    table_arn, table_name = _create_table(ctx, bucket_arn, namespace)

    s3t.put_table_maintenance_configuration(
        tableBucketARN=bucket_arn,
        namespace=namespace,
        name=table_name,
        type="icebergCompaction",
        value={"status": "disabled"},
    )

    cfg_resp = s3t.get_table_maintenance_configuration(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name
    )
    assert cfg_resp["tableARN"] == table_arn, (
        f"config read returned tableARN {cfg_resp['tableARN']!r}, expected {table_arn!r}"
    )
    cfg_status = cfg_resp["configuration"]["icebergCompaction"]["status"]
    assert cfg_status == "disabled", (
        f"config status was {cfg_status!r}, expected lowercase 'disabled'"
    )

    # Capture the raw wire body: TableMaintenanceJobStatusValue's modeled shape is
    # {status, lastRunTimestamp, failureMessage} with no 'settings' member, so botocore's
    # parser silently drops any 'settings' key AWS actually sent -- asserting on job_resp
    # (the parsed dict) can never fail even if the target wrongly echoes the config's
    # settings back into the job view. Assert on the bytes AWS put on the wire instead.
    raw_body = {}

    def _capture_body(response_dict, **_kw):
        raw_body["bytes"] = response_dict["body"]

    s3t.meta.events.register(
        "before-parse.s3tables.GetTableMaintenanceJobStatus", _capture_body
    )
    # The job status is derived from the configuration asynchronously: poll it to 'Disabled'.
    deadline = time.monotonic() + _budget_s(ctx, 60)
    try:
        while True:
            job_resp = s3t.get_table_maintenance_job_status(
                tableBucketARN=bucket_arn, namespace=namespace, name=table_name
            )
            entry = (job_resp.get("status") or {}).get("icebergCompaction") or {}
            if entry.get("status") == "Disabled" or time.monotonic() >= deadline:
                break
            time.sleep(2)
    finally:
        s3t.meta.events.unregister(
            "before-parse.s3tables.GetTableMaintenanceJobStatus", _capture_body
        )

    assert job_resp["tableARN"] == table_arn, (
        f"job status read returned tableARN {job_resp['tableARN']!r}, expected {table_arn!r}"
    )
    job_entry = job_resp["status"]["icebergCompaction"]
    if job_entry["status"] != "Disabled" and _budget_spent(ctx):
        raise TimeoutError("job status settling: the run budget ended first; not graded")
    assert job_entry["status"] == "Disabled", (
        f"job status enum was {job_entry['status']!r}, expected capitalized 'Disabled' -- "
        "distinct from the config's lowercase 'disabled'"
    )

    raw_job_entry = json.loads(raw_body["bytes"])["status"]["icebergCompaction"]
    assert "settings" not in raw_job_entry, (
        f"AWS's own wire response for a disabled job carried a 'settings' key "
        f"({raw_job_entry!r}) -- the job status view must not echo the config's settings"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-"}
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn):
    s3t = ctx.client("s3tables")
    namespace = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))
    return namespace


def _create_table(ctx, bucket_arn, namespace):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    resp = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace,
        name=name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-"},
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
