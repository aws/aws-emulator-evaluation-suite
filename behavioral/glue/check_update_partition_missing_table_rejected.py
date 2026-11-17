"""update-partition-missing-table-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-partition-missing-table-rejected"
GROUP = "partition"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePartition against a table that was never created raises EntityNotFoundException
    naming the table ("Table <name> not found.") and the table stays absent (GetTable:
    "Entity Not Found"); the same call against a real table and partition succeeds.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    # A table and partition in the same database establish that UpdatePartition can succeed
    # at all with this wiring, so the error below is specific to the missing table, not a
    # blanket refusal.
    real_tbl = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": real_tbl,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=real_tbl))
    glue.create_partition(
        DatabaseName=db_name, TableName=real_tbl, PartitionInput={"Values": ["2024"]}
    )
    glue.update_partition(
        DatabaseName=db_name,
        TableName=real_tbl,
        PartitionValueList=["2024"],
        PartitionInput={"Values": ["2024"], "Parameters": {"mark": "updated"}},
    )
    control = glue.get_partition(
        DatabaseName=db_name, TableName=real_tbl, PartitionValues=["2024"]
    )["Partition"]
    assert control["Parameters"].get("mark") == "updated", control

    missing_tbl = ctx.unique_name("sim2real-behav-tbl-missing-")
    code, message = _error_code_and_message(
        lambda: glue.update_partition(
            DatabaseName=db_name,
            TableName=missing_tbl,
            PartitionValueList=["2024"],
            PartitionInput={"Values": ["2024"]},
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    expected_message = f"Table {missing_tbl} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The table UpdatePartition named never comes into existence: GetTable still answers the
    # catalog's generic not-found, not a record the failed call might have half-created.
    table_code, table_message = _error_code_and_message(
        lambda: glue.get_table(DatabaseName=db_name, Name=missing_tbl)
    )
    assert table_code == "EntityNotFoundException", (
        f"UpdatePartition against {missing_tbl!r} must create no table, got {table_code!r}"
    )
    assert table_message == "Entity Not Found", (
        f"expected GetTable message 'Entity Not Found', got {table_message!r}"
    )


def _error_code_and_message(fn):
    """The ``(Code, Message)`` of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
