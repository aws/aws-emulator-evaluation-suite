"""table-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-create-get-delete"
GROUP = 'table'
SERVICES = ['glue']

def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _tolerate_not_found(call):
    """Teardown: a resource the check already deleted is not an error."""
    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_table -> get_table reflects the storage descriptor -> delete_table removes it."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-behav-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}, {"Name": "val", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: _tolerate_not_found(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name)))

    resp = glue.get_table(DatabaseName=db_name, Name=tbl_name)
    table = resp["Table"]
    assert table["Name"] == tbl_name, f"expected table name {tbl_name!r}, got {table['Name']!r}"
    col_names = [c["Name"] for c in table["StorageDescriptor"]["Columns"]]
    assert col_names == ["id", "val"], col_names
    partition_names = [k["Name"] for k in table["PartitionKeys"]]
    assert partition_names == ["dt"], f"expected partition keys ['dt'], got {partition_names}"

    glue.delete_table(DatabaseName=db_name, Name=tbl_name)

    code, message = _refusal(lambda: glue.get_table(DatabaseName=db_name, Name=tbl_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == "Entity Not Found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
