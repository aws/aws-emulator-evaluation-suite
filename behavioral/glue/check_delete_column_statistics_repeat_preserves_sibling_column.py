"""delete-column-statistics-repeat-preserves-sibling-column."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-column-statistics-repeat-preserves-sibling-column"
GROUP = "column-statistics"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeating a column's table-statistics delete stays a no-op for that column alone,
    and a sibling column's statistics are still readable afterward.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-glstat-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-glstat-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "shipment_code", "Type": "string"},
                    {"Name": "parcel_weight_kg", "Type": "double"},
                ]
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    glue.update_column_statistics_for_table(
        DatabaseName=db_name,
        TableName=tbl_name,
        ColumnStatisticsList=[
            {
                "ColumnName": "shipment_code",
                "ColumnType": "string",
                "AnalyzedTime": "2025-03-14T09:30:00Z",
                "StatisticsData": {
                    "Type": "STRING",
                    "StringColumnStatisticsData": {
                        "MaximumLength": 24,
                        "AverageLength": 11.5,
                        "NumberOfNulls": 3,
                        "NumberOfDistinctValues": 18,
                    },
                },
            },
            {
                "ColumnName": "parcel_weight_kg",
                "ColumnType": "double",
                "AnalyzedTime": "2025-03-14T09:31:00Z",
                "StatisticsData": {
                    "Type": "DOUBLE",
                    "DoubleColumnStatisticsData": {
                        "MinimumValue": 0.5,
                        "MaximumValue": 120.75,
                        "NumberOfNulls": 1,
                        "NumberOfDistinctValues": 40,
                    },
                },
            },
        ],
    )

    before = glue.get_column_statistics_for_table(
        DatabaseName=db_name,
        TableName=tbl_name,
        ColumnNames=["shipment_code", "parcel_weight_kg"],
    )
    before_by_name = {e["ColumnName"]: e for e in before["ColumnStatisticsList"]}
    assert set(before_by_name) == {"shipment_code", "parcel_weight_kg"}, before
    assert (
        before_by_name["parcel_weight_kg"]["StatisticsData"]["DoubleColumnStatisticsData"][
            "MaximumValue"
        ]
        == 120.75
    ), before

    glue.delete_column_statistics_for_table(
        DatabaseName=db_name, TableName=tbl_name, ColumnName="shipment_code"
    )
    glue.delete_column_statistics_for_table(
        DatabaseName=db_name, TableName=tbl_name, ColumnName="shipment_code"
    )

    after = glue.get_column_statistics_for_table(
        DatabaseName=db_name,
        TableName=tbl_name,
        ColumnNames=["shipment_code", "parcel_weight_kg"],
    )
    after_by_name = {e["ColumnName"]: e for e in after["ColumnStatisticsList"]}
    assert set(after_by_name) == {"parcel_weight_kg"}, after
    sibling = after_by_name["parcel_weight_kg"]["StatisticsData"]["DoubleColumnStatisticsData"]
    assert sibling["MaximumValue"] == 120.75, after
    assert sibling["MinimumValue"] == 0.5, after
    assert sibling["NumberOfDistinctValues"] == 40, after

    assert len(after["Errors"]) == 1, after
    err = after["Errors"][0]
    assert err["ColumnName"] == "shipment_code", err
    assert err["Error"]["ErrorCode"] == "EntityNotFoundException", err
    assert err["Error"]["ErrorMessage"] == "Statistics do not exist for this column", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
