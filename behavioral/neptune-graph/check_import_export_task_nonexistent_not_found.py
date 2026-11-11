"""import-export-task-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "import-export-task-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetImportTask, CancelImportTask, GetExportTask and CancelExportTask each reject a nonexistent
    taskId with ResourceNotFoundException and the exact message."""
    ng = ctx.client("neptune-graph")
    task_id = "t-0000000000"
    acct = ctx.account

    code, msg = _error(lambda: ng.get_import_task(taskIdentifier=task_id))
    assert code == "ResourceNotFoundException", f"CODE={code!r}"
    expected = f"No import task found for customer [{acct}] with import task id [{task_id}]"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    code2, msg2 = _error(lambda: ng.cancel_import_task(taskIdentifier=task_id))
    assert code2 == "ResourceNotFoundException", f"CODE={code2!r}"
    expected2 = f"No import task found for customer [{acct}] with task id [{task_id}]"
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"

    code3, msg3 = _error(lambda: ng.get_export_task(taskIdentifier=task_id))
    assert code3 == "ResourceNotFoundException", f"CODE={code3!r}"
    expected3 = f"No export task found for customer [{acct}] with export task id [{task_id}]"
    assert msg3 == expected3, f"expected message {expected3!r}, got {msg3!r}"

    code4, msg4 = _error(lambda: ng.cancel_export_task(taskIdentifier=task_id))
    assert code4 == "ResourceNotFoundException", f"CODE={code4!r}"
    expected4 = f"No export task found for customer [{acct}] with task id [{task_id}]"
    assert msg4 == expected4, f"expected message {expected4!r}, got {msg4!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
