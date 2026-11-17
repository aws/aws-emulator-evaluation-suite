"""get-column-statistics-for-table-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-column-statistics-for-table-nonexistent-rejected"
GROUP = "column-statistics"
SERVICES = ["glue"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetColumnStatisticsForTable against a table that was never created in the database is
    refused; the same call against a table that was created and carries recorded statistics
    succeeds and returns the stored values.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-colstat-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    missing_tbl = ctx.unique_name("sim2real-behav-colstat-missing-")
    _TABLE_NOT_FOUND = ("EntityNotFoundException", f"Table {missing_tbl} not found.")
    expect_error(
        lambda: glue.get_column_statistics_for_table(
            DatabaseName=db_name, TableName=missing_tbl, ColumnNames=["amount"]
        ),
        *_TABLE_NOT_FOUND,
    )

    present_tbl = ctx.unique_name("sim2real-behav-colstat-present-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": present_tbl,
            "StorageDescriptor": {"Columns": [{"Name": "amount", "Type": "double"}]},
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=present_tbl))

    glue.update_column_statistics_for_table(
        DatabaseName=db_name,
        TableName=present_tbl,
        ColumnStatisticsList=[
            {
                "ColumnName": "amount",
                "ColumnType": "double",
                "AnalyzedTime": "2026-02-20T09:15:00Z",
                "StatisticsData": {
                    "Type": "DOUBLE",
                    "DoubleColumnStatisticsData": {
                        "MinimumValue": 0.0,
                        "MaximumValue": 250.75,
                        "NumberOfNulls": 3,
                        "NumberOfDistinctValues": 42,
                    },
                },
            }
        ],
    )

    present = glue.get_column_statistics_for_table(
        DatabaseName=db_name, TableName=present_tbl, ColumnNames=["amount"]
    )
    assert present["Errors"] == [], present
    stat = present["ColumnStatisticsList"][0]
    assert stat["ColumnName"] == "amount", stat
    data = stat["StatisticsData"]["DoubleColumnStatisticsData"]
    assert data["MinimumValue"] == 0.0, data
    assert data["MaximumValue"] == 250.75, data
    assert data["NumberOfNulls"] == 3, data
    assert data["NumberOfDistinctValues"] == 42, data


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
