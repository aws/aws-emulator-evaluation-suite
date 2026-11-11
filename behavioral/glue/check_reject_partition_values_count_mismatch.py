"""reject-partition-values-count-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-partition-values-count-mismatch"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_partition with a Values list whose length doesn't match the table's PartitionKeys
    must fail with InvalidInputException, in both directions (too many / too few values), and
    must not create the partition -- while the identical call with the correct arity succeeds.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    # table created with two partition keys, so both "too few" and "too many" stay a
    # genuine arity mismatch -- a single-key table would make "too few" collapse to an
    # empty Values list, which real Glue rejects via ValidationException (a request-shape
    # check), not the InvalidInputException arity check this file exists to exercise.
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [
                {"Name": "year", "Type": "string"},
                {"Name": "month", "Type": "string"},
            ],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    # positive control: an arity-matched partition succeeds on this table
    glue.create_partition(
        DatabaseName=db_name, TableName=tbl_name, PartitionInput={"Values": ["2023", "01"]}
    )
    ctx.on_cleanup(
        lambda: glue.delete_partition(
            DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023", "01"]
        )
    )
    control = glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023", "01"])
    assert control["Partition"]["Values"] == ["2023", "01"], (
        f"the arity-matched positive control must exist, got {control['Partition']}"
    )

    for label, bad_values, expected_create_message, expected_get_message in (
        ("too many values", ["2023", "01", "extra-value"], "The number of partition keys do not match the number of partition values", "Cannot find partition."),
        ("too few values", ["2023"], "The number of partition keys do not match the number of partition values", "Cannot find partition."),
    ):
        code, message = _error_code(
            lambda: glue.create_partition(
                DatabaseName=db_name, TableName=tbl_name, PartitionInput={"Values": bad_values}
            )
        )
        assert code == "InvalidInputException", f"{label}: expected InvalidInputException, got {code}"
        assert message == expected_create_message, (
            f"{label}: expected refusal message {expected_create_message!r}, got {message!r}"
        )
        get_code, get_message = _error_code(
            lambda: glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=bad_values)
        )
        assert get_code == "EntityNotFoundException", (
            f"{label}: the arity-mismatched partition must not have been created, got {get_code}"
        )
        assert get_message == expected_get_message, (
            f"{label}: expected not-found message {expected_get_message!r}, got {get_message!r}"
        )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
