"""get-materialized-view-refresh-task-run-invalid-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-materialized-view-refresh-task-run-invalid-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMaterializedViewRefreshTaskRun with a non-UUID run id raises ValidationException and with
    a well-formed unknown id EntityNotFoundException, each with its exact message.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    code, message = _error(
        lambda: glue.get_materialized_view_refresh_task_run(
            CatalogId=account_id,
            MaterializedViewRefreshTaskRunId="not-a-valid-uuid",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value 'not-a-valid-uuid' at 'materializedViewRefreshTaskRunId' failed to satisfy "
        'constraint: Member must satisfy regular expression pattern: [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a well-formed UUID that simply does not exist yields a different,
    # more specific rejection code.
    code, message = _error(
        lambda: glue.get_materialized_view_refresh_task_run(
            CatalogId=account_id,
            MaterializedViewRefreshTaskRunId="00000000-0000-4000-8000-000000000000",
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected = 'Materialized view refresh task run not found'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
