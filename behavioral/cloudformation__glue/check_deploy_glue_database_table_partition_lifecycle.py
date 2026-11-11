"""deploy-glue-database-table-partition-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-database-table-partition-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----



@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue database, table and partition read back through the Glue Catalog.

    Updates drop the partition, then the table, each while its parent remains, and deleting the
    stack removes the database.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    stack_name = ctx.unique_name("sim2real-behav-cfn-glucat-")
    db_name = ctx.unique_name("sim2real_behav_db_").replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_behav_tbl_").replace("-", "_")
    description = ctx.unique_name("sim2real-desc-")

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Db": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {
                        "Name": db_name,
                        "Description": description,
                        "Parameters": {"sim2real": "true"},
                    },
                },
            },
            "Tbl": {
                "Type": "AWS::Glue::Table",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": {"Ref": "Db"},
                    "TableInput": {
                        "Name": tbl_name,
                        "TableType": "EXTERNAL_TABLE",
                        "PartitionKeys": [{"Name": "dt", "Type": "string"}],
                        "StorageDescriptor": {
                            "Columns": [
                                {"Name": "id", "Type": "bigint"},
                                {"Name": "amount", "Type": "double"},
                            ],
                            "Location": "s3://amzn-s3-demo-bucket/data/",
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                            },
                        },
                    },
                },
            },
            "Part": {
                "Type": "AWS::Glue::Partition",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": {"Ref": "Db"},
                    "TableName": {"Ref": "Tbl"},
                    "PartitionInput": {
                        "Values": ["2024-01-01"],
                        "StorageDescriptor": {
                            "Columns": [
                                {"Name": "id", "Type": "bigint"},
                                {"Name": "amount", "Type": "double"},
                            ],
                            "Location": "s3://amzn-s3-demo-bucket/data/dt=2024-01-01/",
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                            },
                        },
                    },
                },
            },
        },
        "Outputs": {
            "DbRef": {"Value": {"Ref": "Db"}},
            "TblRef": {"Value": {"Ref": "Tbl"}},
            "PartRef": {"Value": {"Ref": "Part"}},
        },
    })

    template_doc = json.loads(template)
    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    columns = [{"Name": "id", "Type": "bigint"}, {"Name": "amount", "Type": "double"}]
    formats = ("org.apache.hadoop.mapred.TextInputFormat",
               "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
               "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe")

    def descriptor(sd):
        return ([{"Name": c["Name"], "Type": c["Type"]} for c in sd["Columns"]], sd["Location"],
                (sd["InputFormat"], sd["OutputFormat"], sd["SerdeInfo"]["SerializationLibrary"]))

    # Each Ref against an independent listing: the catalog's databases, then the database's tables.
    dbs = [(d["Name"], d["CatalogId"], d.get("Description"), d.get("Parameters"))
           for d in paginate(glue, "get_databases", "DatabaseList") if d["Name"] == db_name]
    assert (outputs["DbRef"], dbs) == (db_name, [(db_name, ctx.account, description,
                                                  {"sim2real": "true"})]), (
        f"Ref {outputs['DbRef']!r}, GetDatabases {dbs!r}"
    )
    tables = paginate(glue, "get_tables", "TableList", DatabaseName=db_name)
    got_tbl = [(t["Name"], t["TableType"], [(k["Name"], k["Type"]) for k in t["PartitionKeys"]],
                descriptor(t["StorageDescriptor"])) for t in tables]
    want_tbl = [(tbl_name, "EXTERNAL_TABLE", [("dt", "string")],
                 (columns, "s3://amzn-s3-demo-bucket/data/", formats))]
    assert (outputs["TblRef"], got_tbl) == (tbl_name, want_tbl), (
        f"Ref {outputs['TblRef']!r}, GetTables {got_tbl!r}"
    )
    # Partition Ref: CatalogId|DatabaseName|TableName|<digest of the values>.
    part_ref = outputs["PartRef"].split("|")
    assert part_ref[:3] == [ctx.account, db_name, tbl_name] and len(part_ref) == 4, (
        f"Ref(Part) {outputs['PartRef']!r}"
    )
    parts = paginate(glue, "get_partitions", "Partitions", DatabaseName=db_name,
                     TableName=tbl_name)
    got_parts = [(p["Values"], descriptor(p["StorageDescriptor"])) for p in parts]
    assert got_parts == [(["2024-01-01"], (columns, "s3://amzn-s3-demo-bucket/data/dt=2024-01-01/",
                                           formats))], f"GetPartitions {got_parts!r}"

    # Children first: drop the partition, then the table, each while its parent still answers.
    del template_doc["Resources"]["Part"]
    del template_doc["Outputs"]["PartRef"]
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_doc))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"partition-removing update ended {status!r}"
    left = paginate(glue, "get_partitions", "Partitions", DatabaseName=db_name, TableName=tbl_name)
    assert left == [], f"the dropped partition is still listed: {left!r}"
    kept = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["Name"]
    assert kept == tbl_name, f"table after the partition drop reads {kept!r}"

    del template_doc["Resources"]["Tbl"]
    del template_doc["Outputs"]["TblRef"]
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_doc))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"table-removing update ended {status!r}"
    left = paginate(glue, "get_tables", "TableList", DatabaseName=db_name)
    assert left == [], f"the dropped table is still listed: {left!r}"
    kept = glue.get_database(Name=db_name)["Database"]["Name"]
    assert kept == db_name, f"database after the table drop reads {kept!r}"

    delete_stack(cfn, stack_id)
    not_found = ("EntityNotFoundException", f"Database {db_name} not found.")
    expect_error(lambda: glue.get_database(Name=db_name), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
