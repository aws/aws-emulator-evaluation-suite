"""cancel-export-task-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-export-task-contract"
GROUP = 'errors'
SERVICES = ['rds']

ERR_EXPORT_TASK_NOT_FOUND = "ExportTaskNotFound"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelExportTask with an unknown ExportTaskIdentifier rejects with ExportTaskNotFound
    naming the identifier; DescribeExportTasks succeeding first shows it is not a blanket denial."""
    rds = ctx.client("rds")

    positive = rds.describe_export_tasks()
    assert isinstance(positive.get("ExportTasks"), list), (
        f"DescribeExportTasks did not return an ExportTasks list: {positive!r}"
    )

    bogus_task = ctx.unique_name("sim2real-behav-export-missing-")
    code = None
    message = ""
    try:
        rds.cancel_export_task(ExportTaskIdentifier=bogus_task)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message", "")
    assert code == ERR_EXPORT_TASK_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == f"The export task {bogus_task} doesn't exist.", (
        f"expected the missing identifier {bogus_task!r} in the error message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
