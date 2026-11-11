"""partition-batch-get-omits-missing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partition-batch-get-omits-missing"
GROUP = 'partition'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """batch_get_partition returns only the partitions that exist and silently omits missing ones (no error)."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    glue.create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInput={"Values": ["2019"]},
    )

    resp = glue.batch_get_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionsToGet=[{"Values": ["2019"]}, {"Values": ["1999"]}],
    )

    found_values = [p["Values"] for p in resp["Partitions"]]
    assert ["2019"] in found_values, f"expected ['2019'] among returned partitions, got {found_values}"
    # The missing partition must NOT be fabricated in the response.
    assert ["1999"] not in found_values, f"missing partition was returned: {found_values}"
    assert len(found_values) == 1, f"expected exactly 1 partition returned, got {len(found_values)}: {found_values}"

    # Real Glue does not report missing partitions in UnprocessedKeys; the call
    # succeeds and simply omits them.
    unprocessed_values = [u["Values"] for u in resp.get("UnprocessedKeys", [])]
    assert unprocessed_values == [], (
        f"expected no UnprocessedKeys for a simply-absent partition, got {unprocessed_values}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
