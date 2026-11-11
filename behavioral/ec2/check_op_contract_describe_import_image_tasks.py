"""op-contract-describe-import-image-tasks."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-import-image-tasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImportImageTasks answers with a task list; a well-formed unknown ImportTaskIds entry and an
    unrecognized filter name each match nothing instead of erroring; DryRun answers DryRunOperation
    with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_import_image_tasks()
    assert isinstance(resp.get("ImportImageTasks"), list), (
        f"expected ImportImageTasks to be a list, got {resp.get('ImportImageTasks')!r}"
    )
    assert resp.get("NextToken") in (None, ""), f"expected no NextToken, got {resp.get('NextToken')!r}"

    filtered = ec2.describe_import_image_tasks(Filters=[{"Name": "task-state", "Values": ["completed"]}])
    assert isinstance(filtered.get("ImportImageTasks"), list), (
        f"expected ImportImageTasks to be a list, got {filtered.get('ImportImageTasks')!r}"
    )
    assert all(t["Status"] == "completed" for t in filtered["ImportImageTasks"]), (
        "task-state=completed filter returned a task whose Status is not 'completed'"
    )

    # Boundary: a well-formed but nonexistent import task id does not error, it matches nothing
    # (VM Import/Export's Describe* actions treat an id list as a filter, not a resource lookup).
    bogus_id = "import-ami-0123456789abcdef0"
    empty = ec2.describe_import_image_tasks(ImportTaskIds=[bogus_id])
    assert empty.get("ImportImageTasks") == [], (
        f"expected no tasks for a nonexistent ImportTaskIds entry, got {empty.get('ImportImageTasks')!r}"
    )

    # Boundary: an unrecognized Filters name matches nothing -- it is a 200 with an empty
    # set, neither an error nor a silently-ignored filter that returns everything.
    unknown_filter = ec2.describe_import_image_tasks(
        Filters=[{"Name": "sim2real-not-a-real-filter", "Values": ["x"]}]
    )
    assert unknown_filter.get("ImportImageTasks") == [], (
        f"expected no tasks for an unrecognized filter name, got {unknown_filter.get('ImportImageTasks')!r}"
    )

    # Error boundary: DryRun short-circuits before the task listing is performed.
    code, message = _error(lambda: ec2.describe_import_image_tasks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
