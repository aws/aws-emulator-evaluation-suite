"""batch-get-and-delete-partition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-and-delete-partition"
GROUP = 'partition'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetPartition reports UnprocessedKeys; BatchUpdate/BatchDelete apply per entry."""
    glue = ctx.client("glue")
    db_name, table_name = _make_db_and_partitioned_table(ctx, glue)
    dts = ["2024-06-01", "2024-06-02"]
    for dt in dts:
        glue.create_partition(
            DatabaseName=db_name,
            TableName=table_name,
            PartitionInput={
                "Values": [dt],
                "StorageDescriptor": {
                    "Columns": [{"Name": "id", "Type": "string"}],
                    "Location": f"s3://example-bucket/data/dt={dt}/",
                },
            },
        )

    resp = glue.batch_get_partition(
        DatabaseName=db_name,
        TableName=table_name,
        PartitionsToGet=[{"Values": [dt]} for dt in dts] + [{"Values": ["1999-01-01"]}],
    )
    found = sorted(p["Values"][0] for p in resp["Partitions"])
    assert found == dts, f"BatchGetPartition returned unexpected partitions: {found}"
    unprocessed = [u["Values"][0] for u in resp.get("UnprocessedKeys", [])]
    assert unprocessed == [], (
        "BatchGetPartition must silently omit non-existent keys rather than report them "
        f"as UnprocessedKeys (which signals request-size truncation), got {unprocessed}"
    )
    assert "1999-01-01" not in found, (
        "BatchGetPartition must not fabricate a partition that was never created"
    )

    upd = glue.batch_update_partition(
        DatabaseName=db_name,
        TableName=table_name,
        Entries=[
            {
                "PartitionValueList": ["2024-06-01"],
                "PartitionInput": {
                    "Values": ["2024-06-01"],
                    "StorageDescriptor": {
                        "Columns": [{"Name": "id", "Type": "string"}],
                        "Location": "s3://example-bucket/data/dt=2024-06-01-moved/",
                    },
                },
            }
        ],
    )
    assert not upd.get("Errors"), f"BatchUpdatePartition reported errors: {upd.get('Errors')}"
    moved = glue.get_partition(
        DatabaseName=db_name, TableName=table_name, PartitionValues=["2024-06-01"]
    )["Partition"]
    moved_location = moved["StorageDescriptor"]["Location"]
    assert moved_location == "s3://example-bucket/data/dt=2024-06-01-moved/", (
        f"BatchUpdatePartition should have moved the location, got {moved_location}"
    )

    dele = glue.batch_delete_partition(
        DatabaseName=db_name,
        TableName=table_name,
        PartitionsToDelete=[{"Values": [dt]} for dt in dts],
    )
    assert not dele.get("Errors"), f"BatchDeletePartition reported errors: {dele.get('Errors')}"
    remaining = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert remaining == [], f"partitions should be gone after BatchDeletePartition: {remaining}"

    try:
        glue.get_partition(DatabaseName=db_name, TableName=table_name, PartitionValues=[dts[0]])
        raise AssertionError("get_partition should reject a partition BatchDeletePartition removed")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException for a deleted partition, got {code}"
        )
        expected_message = "Cannot find partition."
        assert message == expected_message, (
            f"expected GetPartition's not-found message {expected_message!r}, got {message!r}"
        )


def _quiet(fn):
    """Best-effort teardown call — the resource may already be gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _make_db_and_partitioned_table(ctx, glue):
    """Create a database plus a dt-partitioned table in it; teardown is registered
    innermost-first so the table goes before the database it lives in."""
    db_name = ctx.unique_name("sim2real-behav-glue-db-")
    table_name = ctx.unique_name("sim2real-behav-glue-tbl-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_database(Name=db_name)))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    )
    return db_name, table_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
