"""delete-column-statistics-task-settings-nonexistent-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-column-statistics-task-settings-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an existing table without column statistics task settings, Get- and
    DeleteColumnStatisticsTaskSettings raise EntityNotFoundException with the exact message, as
    does Delete for a missing table.
    """
    glue = ctx.client("glue")

    db_name = ctx.unique_name("sim2real-glue-cstset-db-")
    table_name = ctx.unique_name("sim2real-glue-cstset-tbl-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "value", "Type": "string"}],
                "Location": f"s3://{ctx.unique_name('sim2real-glue-cstset-bkt-')}/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    # Positive control: the table genuinely exists (GetTable succeeds) -- so the not-found
    # below is specifically about the settings sub-resource, not the table itself.
    described = glue.get_table(DatabaseName=db_name, Name=table_name)
    assert described["Table"]["Name"] == table_name, (
        f"expected GetTable to reflect {table_name!r}, got {described['Table'].get('Name')!r}"
    )

    # Confirm there are, in fact, no settings yet (this table never had any created).
    settings_get_code, settings_get_message = _error(
        lambda: glue.get_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_name
        )
    )
    assert settings_get_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from GetColumnStatisticsTaskSettings on a table "
        f"with no settings, got {settings_get_code!r}"
    )
    expected = "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist"
    assert settings_get_message == expected, (
        f"expected message {expected!r}, got {settings_get_message!r}"
    )

    # Negative: deleting settings that were never created returns EntityNotFoundException,
    # not some generic 400.
    code, message = _error(
        lambda: glue.delete_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_name
        )
    )
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException deleting settings that were never created, got {code!r}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A second nonexistent database/table pair, entirely unrelated to any real resource,
    # produces the identical not-found code -- the assertion isn't an artifact of this one table.
    other_db = ctx.unique_name("sim2real-glue-cstset-nx-db-")
    other_table = ctx.unique_name("sim2real-glue-cstset-nx-tbl-")
    other_code, other_message = _error(
        lambda: glue.delete_column_statistics_task_settings(
            DatabaseName=other_db, TableName=other_table
        )
    )
    assert other_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException deleting settings for an entirely unrelated "
        f"nonexistent database/table pair, got {other_code!r}"
    )
    assert other_message == expected, f"expected message {expected!r}, got {other_message!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

