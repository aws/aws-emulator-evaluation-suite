"""get-tables-lists-created-tables."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-tables-lists-created-tables"
GROUP = 'table'
SERVICES = ['glue']

def _new_database(glue, ctx):
    name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name

def _new_table(glue, ctx, db_name):
    name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda db=db_name, n=name: _drop_table(glue, db, n))
    return name

def _drop_table(glue, db_name, name):
    """Teardown: the check deletes one table itself, so not-found here means already gone."""
    try:
        glue.delete_table(DatabaseName=db_name, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """get_tables on a database returns every table created within it, and none from other databases."""
    glue = ctx.client("glue")
    db_name = _new_database(glue, ctx)
    other_db = _new_database(glue, ctx)

    t1 = _new_table(glue, ctx, db_name)
    t2 = _new_table(glue, ctx, db_name)
    _new_table(glue, ctx, other_db)

    resp = glue.get_tables(DatabaseName=db_name)
    names = {t["Name"] for t in resp["TableList"]}
    assert {t1, t2} <= names, f"expected {t1} and {t2} in {names}"
    assert len(names) == 2, f"expected exactly the 2 tables created in {db_name}, got {names}"

    glue.delete_table(DatabaseName=db_name, Name=t1)

    names_after_delete = {t["Name"] for t in glue.get_tables(DatabaseName=db_name)["TableList"]}
    assert names_after_delete == {t2}, f"expected only {t2} after deleting {t1}, got {names_after_delete}"

    try:
        glue.get_table(DatabaseName=db_name, Name=t1)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"get_table on the deleted {t1} succeeded; it must be refused")
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException for deleted {t1}, got {code}"
    expected = 'Entity Not Found'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
