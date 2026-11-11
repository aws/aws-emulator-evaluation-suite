"""deploy-glue-database-via-cloudformation-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-glue-database-via-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A database deployed via AWS::Glue::Database is usable immediately: GetDatabase
    returns it and CreateTable referencing it succeeds -- not just CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    db_name = ctx.unique_name("sim2real-behav-db-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    table_name = ctx.unique_name("sim2real-behav-tbl-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "GlueDB": {
                    "Type": "AWS::Glue::Database",
                    "Properties": {
                        "CatalogId": account_id,
                        "DatabaseInput": {
                            "Name": db_name,
                            "Description": "sim2real behavioral fidelity test database",
                        },
                    },
                }
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wfs(ctx, stack_name)

    # The database must be immediately usable, not just present in a "complete" stack.
    described = glue.get_database(Name=db_name)
    assert described["Database"]["Name"] == db_name
    assert described["Database"]["Description"] == "sim2real behavioral fidelity test database", (
        f"expected the templated Description, got {described['Database'].get('Description')!r}"
    )

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://sim2real-behav-placeholder/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    got_table = glue.get_table(DatabaseName=db_name, Name=table_name)
    assert got_table["Table"]["Name"] == table_name
    assert got_table["Table"]["DatabaseName"] == db_name

    # A second, independent read at the destination: the table is visible in its
    # database's listing, not just retrievable by name.
    listed = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert any(t["Name"] == table_name for t in listed), (
        f"table {table_name!r} not present in get_tables listing for {db_name!r}: "
        f"{[t['Name'] for t in listed]!r}"
    )


def _wfs(ctx, sn, t=180.0):
    cfn = ctx.client("cloudformation")
    dl = time.monotonic() + t
    ls = None
    while time.monotonic() < dl:
        ss = cfn.describe_stacks(StackName=sn).get("Stacks", [])
        if not ss:
            time.sleep(2)
            continue
        ls = ss[0]["StackStatus"]
        if ls == "CREATE_COMPLETE":
            return ls
        if ls in ("CREATE_FAILED", "ROLLBACK_COMPLETE"):
            r = ss[0].get("StackStatusReason", "")
            try:
                ev = cfn.describe_stack_events(StackName=sn)["StackEvents"]
                cf = [e.get("ResourceStatusReason") for e in ev if e.get("ResourceStatus") == "CREATE_FAILED"]
                r = cf[0] if cf else r
            except Exception:
                pass
            raise AssertionError((r or "")[:500])
        time.sleep(3)
    raise AssertionError(ls)


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return
        stacks = resp.get("Stacks", [])
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
