"""delete-column-statistics-for-table-missing-table-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-column-statistics-for-table-missing-table-rejected"
GROUP = "column-statistics"
SERVICES = ["glue"]

def _expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``code``/``message``; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, err
        assert err["Message"] == message, err
        return
    raise AssertionError(f"expected refusal {code}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting column statistics for a table that was never created is refused,
    while the same call against a table that exists succeeds.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-glmiss-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    missing_tbl = ctx.unique_name("sim2real-behav-glmiss-ghost-")
    _MISSING_TABLE = ("EntityNotFoundException", f"Table {missing_tbl} not found.")
    _expect_error(
        lambda: glue.delete_column_statistics_for_table(
            DatabaseName=db_name, TableName=missing_tbl, ColumnName="region_code"
        ),
        *_MISSING_TABLE,
    )

    real_tbl = ctx.unique_name("sim2real-behav-glmiss-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": real_tbl,
            "StorageDescriptor": {"Columns": [{"Name": "region_code", "Type": "string"}]},
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=real_tbl))

    glue.update_column_statistics_for_table(
        DatabaseName=db_name,
        TableName=real_tbl,
        ColumnStatisticsList=[
            {
                "ColumnName": "region_code",
                "ColumnType": "string",
                "AnalyzedTime": "2025-07-02T16:45:00Z",
                "StatisticsData": {
                    "Type": "STRING",
                    "StringColumnStatisticsData": {
                        "MaximumLength": 6,
                        "AverageLength": 3.0,
                        "NumberOfNulls": 0,
                        "NumberOfDistinctValues": 9,
                    },
                },
            }
        ],
    )

    # the control: the identical delete succeeds against a table that exists
    glue.delete_column_statistics_for_table(
        DatabaseName=db_name, TableName=real_tbl, ColumnName="region_code"
    )
    after = glue.get_column_statistics_for_table(
        DatabaseName=db_name, TableName=real_tbl, ColumnNames=["region_code"]
    )
    assert after["ColumnStatisticsList"] == [], after
    assert after["Errors"][0]["Error"]["ErrorCode"] == "EntityNotFoundException", after
    assert after["Errors"][0]["Error"]["ErrorMessage"] == "Statistics do not exist for this column", after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
