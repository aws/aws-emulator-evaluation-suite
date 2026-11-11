"""op-contract-describe-import-snapshot-tasks."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-import-snapshot-tasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImportSnapshotTasks returns a well-formed (possibly empty) task set, and
    DryRun short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_import_snapshot_tasks()
    tasks = resp["ImportSnapshotTasks"]
    assert isinstance(tasks, list), f"expected ImportSnapshotTasks to be a list, got {type(tasks).__name__}"
    next_token = resp.get("NextToken")
    assert next_token in (None, ""), f"expected no NextToken with no tasks in flight, got {next_token!r}"

    filtered = ec2.describe_import_snapshot_tasks(Filters=[{"Name": "tag-key", "Values": ["sim2real-nonexistent"]}])
    assert filtered["ImportSnapshotTasks"] == [], (
        f"expected no tasks to match a nonexistent tag-key filter, got {filtered['ImportSnapshotTasks']!r}"
    )

    # Error boundary: DryRun short-circuits before the task listing is performed.
    code, message = _error(lambda: ec2.describe_import_snapshot_tasks(DryRun=True))
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
