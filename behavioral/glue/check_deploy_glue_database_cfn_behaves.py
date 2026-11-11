"""deploy-glue-database-cfn-behaves."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "deploy-glue-database-cfn-behaves"
GROUP = "deploy"
SERVICES = ["glue"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DatabaseName:
    Type: String
Resources:
  GlueDatabase:
    Type: AWS::Glue::Database
    Properties:
      CatalogId: !Ref AWS::AccountId
      DatabaseInput:
        Name: !Ref DatabaseName
        Description: "sim2real behavioral check database"
Outputs:
  DatabaseNameOut:
    Value: !Ref DatabaseName
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A database deployed via AWS::Glue::Database is immediately usable: a table
    can be created inside it and read back correctly (Catalog metadata, not just
    CFN CREATE_COMPLETE)."""
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    db_name = ctx.unique_name("sim2real-glue-db-")
    stack_name = ctx.unique_name("sim2real-glue-dbstack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420})

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE,
                      Parameters=[{"ParameterKey": "DatabaseName", "ParameterValue": db_name}])

    ctx.on_cleanup(_cleanup_stack)

    try:
        cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})
    except Exception:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e.get('LogicalResourceId')}: {e.get('ResourceStatus')} - {e.get('ResourceStatusReason')}"
            for e in events
            if e.get("ResourceStatusReason")
        ]
        raise AssertionError("stack create failed: " + " | ".join(reasons))

    # Database exists and is readable through the Glue Catalog API, and the
    # DatabaseInput properties from the template are represented, not just CREATE_COMPLETE.
    db = glue.get_database(Name=db_name)["Database"]
    assert db["Name"] == db_name, f"expected Name={db_name!r}, got {db.get('Name')!r}"
    assert db["Description"] == "sim2real behavioral check database", (
        f"expected Description from the templated DatabaseInput, got {db.get('Description')!r}"
    )
    assert db["CatalogId"] == account_id, f"expected CatalogId={account_id!r}, got {db.get('CatalogId')!r}"

    # A table can be created INSIDE the CFN-deployed database and read back.
    table_name = ctx.unique_name("sim2real-glue-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "amount", "Type": "double"},
                ],
                "Location": f"s3://sim2real-glue-behav-nonexistent/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    got = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert got["Name"] == table_name, f"expected table Name={table_name!r}, got {got.get('Name')!r}"
    assert got["DatabaseName"] == db_name, (
        f"expected table DatabaseName={db_name!r}, got {got.get('DatabaseName')!r}"
    )
    col_names = [c["Name"] for c in got["StorageDescriptor"]["Columns"]]
    assert col_names == ["id", "amount"], f"expected columns ['id', 'amount'], got {col_names!r}"

    # And it shows up when listing tables in that database.
    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert any(t["Name"] == table_name for t in tables), (
        f"expected {table_name!r} in get_tables listing, got {[t['Name'] for t in tables]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
