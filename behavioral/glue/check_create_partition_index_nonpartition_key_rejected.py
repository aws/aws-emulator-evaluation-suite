"""create-partition-index-nonpartition-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-partition-index-nonpartition-key-rejected"
GROUP = 'partition'
SERVICES = ['glue']


def _storage(columns):
    return {
        "Columns": columns,
        "Location": "s3://example-bucket/data/",
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
        },
    }


def _index_names(glue, db_name, tbl_name):
    return sorted(
        i["IndexName"]
        for i in glue.get_partition_indexes(DatabaseName=db_name, TableName=tbl_name).get(
            "PartitionIndexDescriptorList", []
        )
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePartitionIndex over a data column raises InvalidInputException with the exact message
    and creates no index, while an index over the partition key "dt" is created with Keys ["dt"].
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    # DeleteTable removes the table's partition indexes with it, so the table/database
    # teardown below is sufficient — a separate DeletePartitionIndex cleanup would race
    # the index's own CREATING state.
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    assert _index_names(glue, db_name, tbl_name) == [], (
        "a freshly created table must have no partition indexes"
    )

    bad_index = "sim2real-behav-idx-on-data-column"
    try:
        glue.create_partition_index(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionIndex={"IndexName": bad_index, "Keys": ["id"]},
        )
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidInputException", (
        "CreatePartitionIndex over the data column 'id' must be refused with "
        f"InvalidInputException, got {code}"
    )
    expected = "IndexKeys not a part of PartitionColumns. Verify the indexKeys : [id]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no index was created, not even a failed/rejected one.
    assert bad_index not in _index_names(glue, db_name, tbl_name), (
        f"the rejected index was still registered: {_index_names(glue, db_name, tbl_name)}"
    )

    # Control: the same call over the real partition key is accepted and shows up.
    good_index = "sim2real-behav-idx-on-dt"
    glue.create_partition_index(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionIndex={"IndexName": good_index, "Keys": ["dt"]},
    )
    names = _index_names(glue, db_name, tbl_name)
    assert names == [good_index], (
        f"an index over the partition key 'dt' must be the only index present, got {names}"
    )
    described = [
        i
        for i in glue.get_partition_indexes(DatabaseName=db_name, TableName=tbl_name)[
            "PartitionIndexDescriptorList"
        ]
        if i["IndexName"] == good_index
    ][0]
    assert [k["Name"] for k in described["Keys"]] == ["dt"], (
        f"the accepted index must report its keys as ['dt'], got {described}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
