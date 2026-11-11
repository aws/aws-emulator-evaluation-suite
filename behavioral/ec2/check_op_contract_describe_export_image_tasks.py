"""op-contract-describeExportImageTasks."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeExportImageTasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeExportImageTasks returns the well-formed collection shape and treats a bogus
    task ID as a non-matching filter rather than a lookup error."""
    ec2 = ctx.client("ec2")

    # --- success path: no export-image task exists for our fresh account/region slice, but the
    # response shape (key + type) must be correct, and an owner-self filter must be honored ---
    resp = ec2.describe_export_image_tasks()
    assert "ExportImageTasks" in resp, f"expected ExportImageTasks key in response, got keys {sorted(resp)}"
    assert isinstance(resp["ExportImageTasks"], list), (
        f"expected ExportImageTasks to be a list, got {type(resp['ExportImageTasks'])!r}"
    )

    filtered = ec2.describe_export_image_tasks(
        Filters=[{"Name": "task-state", "Values": ["completed"]}]
    )
    assert isinstance(filtered["ExportImageTasks"], list), (
        f"expected a filtered call to also return a list, got {type(filtered['ExportImageTasks'])!r}"
    )

    # --- boundary: a well-formed but nonexistent export-image task ID is treated as an
    # ID filter (like the Filters parameter), not a specific-resource lookup -- it must
    # not raise, it must simply match nothing ---
    bogus_id = "export-ami-0123456789abcdef0"
    empty = ec2.describe_export_image_tasks(ExportImageTaskIds=[bogus_id])
    assert empty["ExportImageTasks"] == [], (
        f"expected a nonexistent ExportImageTaskIds entry to match nothing (empty list), "
        f"got {empty['ExportImageTasks']!r} -- a lookup error or a stale match would both be wrong"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
