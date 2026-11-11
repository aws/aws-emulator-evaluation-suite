"""op-contract-describeExportTasks."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeExportTasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeExportTasks returns the well-formed collection shape and treats a bogus
    task ID as a non-matching filter rather than a lookup error."""
    ec2 = ctx.client("ec2")

    # --- success path: no export (instance/VM) task exists, but the response shape must be right ---
    resp = ec2.describe_export_tasks()
    assert "ExportTasks" in resp, f"expected an ExportTasks key in the response, got keys {sorted(resp)}"
    assert isinstance(resp["ExportTasks"], list), (
        f"expected ExportTasks to be a list, got {type(resp['ExportTasks']).__name__}"
    )

    # --- boundary: a well-formed but nonexistent export task ID is treated as an ID filter,
    # not a specific-resource lookup -- it must not raise, it must simply match nothing ---
    bogus_id = "export-i-0123456789abcdef0"
    empty = ec2.describe_export_tasks(ExportTaskIds=[bogus_id])
    assert empty["ExportTasks"] == [], (
        f"expected ExportTaskIds=[{bogus_id!r}] to match nothing (not raise), "
        f"got {empty['ExportTasks']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
