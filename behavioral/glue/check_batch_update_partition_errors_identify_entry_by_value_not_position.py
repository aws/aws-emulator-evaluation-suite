"""batch-update-partition-errors-identify-entry-by-value-not-position."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-update-partition-errors-identify-entry-by-value-not-position"
GROUP = "partition"
SERVICES = ["glue"]


def _entry_error(errors, missing_value):
    """Locate the one Errors entry naming missing_value, regardless of where it sits in the list."""
    matches = [e for e in errors if e.get("PartitionValueList") == [missing_value]]
    assert len(matches) == 1, (
        f"expected exactly one Errors entry identified by value {missing_value!r}, got {errors}"
    )
    return matches[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdatePartition applies every real entry and reports the missing one by value, not slot.
    GetPartitions confirms no partition was fabricated for it, across two differently ordered calls."""
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
            "PartitionKeys": [{"Name": "shard", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))
    for shard in ("s-00", "s-01"):
        glue.create_partition(
            DatabaseName=db_name, TableName=tbl_name, PartitionInput={"Values": [shard]}
        )

    def _update(entries):
        return glue.batch_update_partition(
            DatabaseName=db_name, TableName=tbl_name, Entries=entries
        )

    def _round(shard):
        part = glue.get_partition(
            DatabaseName=db_name, TableName=tbl_name, PartitionValues=[shard]
        )["Partition"]
        return part["Parameters"].get("round")

    def _existing_shards():
        parts = glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)["Partitions"]
        return sorted(p["Values"][0] for p in parts)

    # Round 1: the missing entry sits between the two real updates.
    resp1 = _update(
        [
            {
                "PartitionValueList": ["s-00"],
                "PartitionInput": {"Values": ["s-00"], "Parameters": {"round": "1a"}},
            },
            {
                "PartitionValueList": ["s-98"],
                "PartitionInput": {"Values": ["s-98"], "Parameters": {"round": "x"}},
            },
            {
                "PartitionValueList": ["s-01"],
                "PartitionInput": {"Values": ["s-01"], "Parameters": {"round": "1b"}},
            },
        ]
    )
    errors1 = resp1.get("Errors", [])
    assert len(errors1) == 1, f"expected exactly one Errors entry, got {errors1!r}"
    err1 = _entry_error(errors1, "s-98")
    assert err1["ErrorDetail"]["ErrorCode"] == "EntityNotFoundException", err1
    msg1 = err1["ErrorDetail"].get("ErrorMessage")
    expected_msg1 = "Partition [s-98] not found"
    assert msg1 == expected_msg1, f"expected {expected_msg1!r}, got {msg1!r}"

    round1_00, round1_01 = _round("s-00"), _round("s-01")
    assert round1_00 == "1a", f"s-00 must carry round 1's own update, got {round1_00!r}"
    assert round1_01 == "1b", f"s-01 must carry round 1's own update, got {round1_01!r}"
    shards1 = _existing_shards()
    assert shards1 == ["s-00", "s-01"], (
        f"GetPartitions must not fabricate a partition for the missing entry, got {shards1!r}"
    )

    # Round 2: a different missing value, the two real entries swapped and the missing one moved
    # to the front — the error must still be found by value, not by its slot in the batch.
    resp2 = _update(
        [
            {
                "PartitionValueList": ["s-99"],
                "PartitionInput": {"Values": ["s-99"], "Parameters": {"round": "y"}},
            },
            {
                "PartitionValueList": ["s-01"],
                "PartitionInput": {"Values": ["s-01"], "Parameters": {"round": "2b"}},
            },
            {
                "PartitionValueList": ["s-00"],
                "PartitionInput": {"Values": ["s-00"], "Parameters": {"round": "2a"}},
            },
        ]
    )
    errors2 = resp2.get("Errors", [])
    assert len(errors2) == 1, f"expected exactly one Errors entry, got {errors2!r}"
    err2 = _entry_error(errors2, "s-99")
    assert err2["ErrorDetail"]["ErrorCode"] == "EntityNotFoundException", err2
    msg2 = err2["ErrorDetail"].get("ErrorMessage")
    expected_msg2 = "Partition [s-99] not found"
    assert msg2 == expected_msg2, f"expected {expected_msg2!r}, got {msg2!r}"

    round2_00, round2_01 = _round("s-00"), _round("s-01")
    assert round2_00 == "2a", f"s-00 must carry round 2's own update, got {round2_00!r}"
    assert round2_01 == "2b", f"s-01 must carry round 2's own update, got {round2_01!r}"
    shards2 = _existing_shards()
    assert shards2 == ["s-00", "s-01"], (
        f"GetPartitions must not fabricate a partition for either missing entry, got {shards2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
