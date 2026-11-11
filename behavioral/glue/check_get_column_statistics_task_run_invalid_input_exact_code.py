"""get-column-statistics-task-run-invalid-input-exact-code."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-column-statistics-task-run-invalid-input-exact-code"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetColumnStatisticsTaskRun with a newline-embedded run id raises ValidationException and with
    two well-formed unknown ids EntityNotFoundException, each with its exact message.
    """
    glue = ctx.client("glue")

    malformed_id = "bad\nrun\nid"
    malformed_code, malformed_message = _error(
        lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=malformed_id)
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a newline-embedded run id {malformed_id!r}, "
        f"got {malformed_code!r}"
    )
    expected = (
        '1 validation error detected: Value '
        f"'{malformed_id}'"
        " at 'columnStatisticsTaskRunId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0020-\\uD7FF\\uE000-\\uFFFD\\uD800\\uDC00-\\uDBFF\\uDFFF\\t]*"
    )
    assert malformed_message == expected, (
        f"expected message {expected!r}, got {malformed_message!r}"
    )

    # Well-formed (UUID-shaped) but nonexistent -> EntityNotFoundException, not the same code
    # as the malformed-input path above.
    nonexistent_id = str(uuid.uuid4())
    nonexistent_code, nonexistent_message = _error(
        lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=nonexistent_id)
    )
    assert nonexistent_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for well-formed nonexistent run id "
        f"{nonexistent_id!r}, got {nonexistent_code!r}"
    )
    expected = 'For given input ColumnStatisticsTaskRunId, associated ColumnStatisticsTaskRun does not exist'
    assert nonexistent_message == expected, (
        f"expected message {expected!r}, got {nonexistent_message!r}"
    )
    assert nonexistent_code != malformed_code, (
        "malformed-input and not-found paths must return distinct codes, both were "
        f"{nonexistent_code!r}"
    )

    # A second, differently-shaped but still well-formed UUID also resolves to the same
    # not-found family, confirming this isn't a one-off fluke of the particular id chosen.
    another_nonexistent_id = str(uuid.uuid4())
    assert another_nonexistent_id != nonexistent_id, "uuid4 collided across two calls"
    another_code, another_message = _error(
        lambda: glue.get_column_statistics_task_run(
            ColumnStatisticsTaskRunId=another_nonexistent_id
        )
    )
    assert another_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for a second well-formed nonexistent run id "
        f"{another_nonexistent_id!r}, got {another_code!r}"
    )
    expected = 'For given input ColumnStatisticsTaskRunId, associated ColumnStatisticsTaskRun does not exist'
    assert another_message == expected, f"expected message {expected!r}, got {another_message!r}"


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


