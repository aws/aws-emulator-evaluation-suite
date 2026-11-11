"""get-partitions-expression-like-and-not-equals."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-partitions-expression-like-and-not-equals"
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
    return sorted(p["Values"][0] for p in glue.get_partitions(**kwargs)["Partitions"])


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPartitions Expression implements LIKE 'us-%' and <>, returning exactly the matching string
    partitions, and returns [] for a valid filter that matches nothing.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(
        DatabaseInput={"Name": db_name},
        Tags={"sim2real-behav-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
            "PartitionKeys": [{"Name": "region", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    regions = ["eu-west-1", "us-east-1", "us-west-2"]
    for region in regions:
        glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": [region],
                "StorageDescriptor": _storage(
                    [{"Name": "id", "Type": "bigint"}],
                    location="s3://example-bucket/data/region=%s/" % region,
                ),
            },
        )

    # Control: unfiltered returns everything, so the table really has all three partitions.
    assert _filtered(glue, db_name, tbl_name) == regions, (
        f"unfiltered GetPartitions must return {regions}"
    )

    like_us = _filtered(glue, db_name, tbl_name, "region LIKE 'us-%'")
    assert like_us == ["us-east-1", "us-west-2"], (
        f"LIKE 'us-%' must match exactly the two us- partitions, got {like_us}"
    )

    not_equal = _filtered(glue, db_name, tbl_name, "region <> 'us-east-1'")
    assert not_equal == ["eu-west-1", "us-west-2"], (
        f"<> 'us-east-1' must exclude only that partition, got {not_equal}"
    )

    # Valid expression, no matches: must be an empty list, not an error and not the full set.
    no_match = _filtered(glue, db_name, tbl_name, "region LIKE 'ap-%'")
    assert no_match == [], (
        f"a valid Expression matching nothing must return [], got {no_match}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
