"""describe-export-tasks."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-export-tasks"
GROUP = 'snapshots'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeExportTasks succeeds unfiltered and for an unknown ExportTaskIdentifier (empty result), a
    MaxRecords below 20 is rejected by the service rather than clamped, and MaxRecords=20 is accepted."""
    rds = ctx.client("rds")
    resp = rds.describe_export_tasks()
    assert "ExportTasks" in resp, f"DescribeExportTasks response missing ExportTasks: {resp!r}"
    assert isinstance(resp["ExportTasks"], list), f"ExportTasks is not a list: {resp['ExportTasks']!r}"

    bogus_task = ctx.unique_name("sim2real-behav-exporttask-missing-")
    resp2 = rds.describe_export_tasks(ExportTaskIdentifier=bogus_task)
    assert resp2["ExportTasks"] == [], (
        f"filtering by an unknown ExportTaskIdentifier should return an empty list, "
        f"got {resp2['ExportTasks']!r}"
    )

    # Client-side parameter validation would otherwise short-circuit MaxRecords=5 before it
    # reaches the wire (MaxRecords carries a min:20/max:100 range constraint in the model), so
    # the rejection is exercised through a client with validation disabled.
    unvalidated = ctx.client("rds", config=Config(parameter_validation=False))
    err = _rejection(lambda: unvalidated.describe_export_tasks(MaxRecords=5))
    assert err.get("Code") == "InvalidParameterValue", f"unexpected error for MaxRecords=5: {err}"
    assert err.get("Message") == (
        "1 validation error detected: Value '5' at 'maxRecords' failed to satisfy constraint: "
        "Member must have value greater than or equal to 20"
    ), f"unexpected InvalidParameterValue message: {err}"

    # Positive control: the documented minimum (20) is accepted, not rejected.
    resp3 = unvalidated.describe_export_tasks(MaxRecords=20)
    assert "ExportTasks" in resp3, f"MaxRecords=20 (the documented minimum) was rejected: {resp3!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
