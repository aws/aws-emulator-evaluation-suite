"""get-partitions-expression-numeric-coercion."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-partitions-expression-numeric-coercion"
GROUP = 'partition'
SERVICES = ['glue']


def _storage(columns, location="s3://example-bucket/data/"):
    return {
        "Columns": columns,
        "Location": location,
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
        },
    }


def _filtered(glue, db_name, tbl_name, expression=None):
    kwargs = {"DatabaseName": db_name, "TableName": tbl_name}
    if expression is not None:
        kwargs["Expression"] = expression
    return sorted(
        int(p["Values"][0]) for p in glue.get_partitions(**kwargs)["Partitions"]
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPartitions compares an int partition key numerically: over 9, 10 and 100, "yr > 9" gives
    [10, 100], "yr < 100" gives [9, 10] and "yr BETWEEN 10 AND 100" gives [10, 100].
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
            "PartitionKeys": [{"Name": "yr", "Type": "int"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    values = ["9", "10", "100"]
    for yr in values:
        glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": [yr],
                "StorageDescriptor": _storage(
                    [{"Name": "id", "Type": "bigint"}],
                    location="s3://example-bucket/data/yr=%s/" % yr,
                ),
            },
        )

    # Control: unfiltered returns all three, so the partitions exist and are readable.
    unfiltered = _filtered(glue, db_name, tbl_name)
    assert unfiltered == [9, 10, 100], (
        f"unfiltered GetPartitions must return all three int partitions, got {unfiltered}"
    )

    greater = _filtered(glue, db_name, tbl_name, "yr > 9")
    assert greater == [10, 100], (
        f"int partition key must compare numerically: 'yr > 9' should be [10, 100], got {greater} "
        "(a lexicographic comparator returns [])"
    )

    less = _filtered(glue, db_name, tbl_name, "yr < 100")
    assert less == [9, 10], (
        f"int partition key must compare numerically: 'yr < 100' should be [9, 10], got {less} "
        "(a lexicographic comparator returns [10])"
    )

    between = _filtered(glue, db_name, tbl_name, "yr BETWEEN 10 AND 100")
    assert between == [10, 100], (
        f"BETWEEN on an int partition key must be numeric and inclusive, got {between}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
