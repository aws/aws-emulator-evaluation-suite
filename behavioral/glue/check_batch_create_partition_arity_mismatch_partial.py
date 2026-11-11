"""batch-create-partition-arity-mismatch-partial."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-create-partition-arity-mismatch-partial"
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


def _partition_input(values):
    return {
        "Values": values,
        "StorageDescriptor": _storage(
            [{"Name": "id", "Type": "bigint"}],
            location="s3://example-bucket/data/%s/" % "-".join(values),
        ),
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An arity-mismatched entry fails the whole BatchCreatePartition request (nothing is created,
    not even the valid entry beside it), while a duplicate entry fails per-entry and the rest land.
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
            "PartitionKeys": [
                {"Name": "yr", "Type": "string"},
                {"Name": "mo", "Type": "string"},
            ],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    def _listed():
        return sorted(
            tuple(p["Values"])
            for p in glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)["Partitions"]
        )

    def _get_partition_error(values):
        """GetPartition's (Code, Message) for a partition that must not exist; an unexpected
        SUCCESS raises, so a partition created by a refused batch fails loudly."""
        try:
            got = glue.get_partition(
                DatabaseName=db_name, TableName=tbl_name, PartitionValues=values
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        raise AssertionError(f"GetPartition {values!r} unexpectedly SUCCEEDED: {got.get('Partition')!r}")

    # --- break exactly one thing: one entry's Values arity, in both directions ---------
    for label, bad_values in (
        ("too few values", ["2024"]),
        ("too many values", ["2024", "01", "extra"]),
    ):
        try:
            resp = glue.batch_create_partition(
                DatabaseName=db_name,
                TableName=tbl_name,
                PartitionInputList=[
                    _partition_input(["2024", "01"]),  # valid: 2 keys, 2 values
                    _partition_input(bad_values),  # invalid for a 2-key table
                ],
            )
            code, message, errors = None, "", resp.get("Errors", [])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message, errors = err.get("Code"), err.get("Message", ""), None
        assert code == "InvalidInputException", (
            f"{label}: the whole request must be refused with InvalidInputException, got "
            f"{code!r} (Errors={errors!r})"
        )
        expected_message = "The number of partition keys do not match the number of partition values"
        assert message == expected_message, (
            f"{label}: expected the arity refusal message {expected_message!r}, got {message!r}"
        )
        # Arity is validated for the whole request before any entry is applied: all-or-nothing.
        valid_error = _get_partition_error(["2024", "01"])
        assert valid_error == ("EntityNotFoundException", "Cannot find partition."), (
            f"{label}: the valid entry beside the bad one must not be created; GetPartition "
            f"returned {valid_error!r}"
        )
        bad_error = _get_partition_error(bad_values)
        assert bad_error == ("EntityNotFoundException", "Cannot find partition."), (
            f"{label}: the arity-mismatched partition must not exist; GetPartition returned {bad_error!r}"
        )
        assert _listed() == [], f"{label}: a refused batch created {_listed()}"

    # --- control: the identical valid entries succeed once the bad one is dropped ------
    clean = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[_partition_input(["2024", "01"]), _partition_input(["2024", "02"])],
    )
    assert clean.get("Errors", []) == [], (
        f"an all-valid BatchCreatePartition must report no errors, got {clean.get('Errors')}"
    )
    assert _listed() == [("2024", "01"), ("2024", "02")], (
        f"expected exactly the two valid partitions, got {_listed()}"
    )

    # --- the per-entry Errors path is real, just not for arity: a DUPLICATE entry fails
    #     alone and the valid entry beside it IS created -------------------------------
    partial = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[
            _partition_input(["2024", "01"]),  # already exists
            _partition_input(["2024", "03"]),  # new
        ],
    )
    errors = partial.get("Errors", [])
    assert len(errors) == 1, (
        f"exactly the duplicate entry must fail per-entry, got {len(errors)}: {errors}"
    )
    assert errors[0]["PartitionValues"] == ["2024", "01"], (
        f"the error must identify the offending entry by its Values, got {errors[0]}"
    )
    assert errors[0]["ErrorDetail"]["ErrorCode"] == "AlreadyExistsException", (
        f"a duplicate entry must be reported as AlreadyExistsException, got {errors[0]}"
    )
    expected_dup = "Partition already exists."
    assert errors[0]["ErrorDetail"].get("ErrorMessage") == expected_dup, (
        f"expected the duplicate entry's ErrorMessage {expected_dup!r}, got {errors[0]}"
    )
    assert _listed() == [("2024", "01"), ("2024", "02"), ("2024", "03")], (
        f"the valid entry of a partially-failed batch must be created, got {_listed()}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
