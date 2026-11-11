"""op-contract-cancel-export-task."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancel-export-task"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelExportTask on a well-formed export task ID that does not exist fails with
    InvalidExportTaskID.NotFound and the exact message naming that ID."""
    ec2 = ctx.client("ec2")

    code, message = _error(
        lambda: ec2.cancel_export_task(ExportTaskId="export-i-0123456789abcdef0")
    )
    assert code == "InvalidExportTaskID.NotFound", f"expected InvalidExportTaskID.NotFound, got {code}"
    assert message == "The export-instance-task ID 'export-i-0123456789abcdef0' does not exist", message


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
