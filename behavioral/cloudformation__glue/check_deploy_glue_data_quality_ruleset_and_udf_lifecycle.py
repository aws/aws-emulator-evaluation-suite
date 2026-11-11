"""deploy-glue-data-quality-ruleset-and-udf-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-data-quality-ruleset-and-udf-lifecycle"
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



def _pages(op, key, **kw):
    """Every ``key`` item across NextToken pages of ``op``, which has no botocore paginator."""
    items, token = [], None
    while True:
        page = op(**kw, **({"NextToken": token} if token else {}))
        items.extend(page.get(key, []))
        token = page.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue data quality ruleset and user-defined function read back as templated.

    An update dropping both removes them while their table remains, and deleting the stack
    removes the database.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    stack_name = ctx.unique_name("sim2real-behav-cfn-gluedq-")
    db_name = ctx.unique_name("sim2real_behav_dqdb_").replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_behav_dqtbl_").replace("-", "_")
    dq_name = ctx.unique_name("sim2real_behav_dq_").replace("-", "_")
    fn_name = ctx.unique_name("sim2real_behav_fn_").replace("-", "_")
    owner_name = ctx.unique_name("sim2real-behav-owner-")
    ruleset_dqdl = "Rules = [ RowCount > 0 ]"
    class_name = "com.sim2real.udf.ExampleFn"

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Db": {
                "Type": "AWS::Glue::Database",
                "Properties": {"CatalogId": {"Ref": "AWS::AccountId"}, "DatabaseInput": {"Name": db_name}},
            },
            "Tbl": {
                "Type": "AWS::Glue::Table",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": {"Ref": "Db"},
                    "TableInput": {
                        "Name": tbl_name,
                        "StorageDescriptor": {
                            "Columns": [{"Name": "id", "Type": "string"}],
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
            "Dq": {
                "Type": "AWS::Glue::DataQualityRuleset",
                "Properties": {
                    "Name": dq_name,
                    "Ruleset": ruleset_dqdl,
                    "TargetTable": {"DatabaseName": {"Ref": "Db"}, "TableName": {"Ref": "Tbl"}},
                },
            },
            "Udf": {
                "Type": "AWS::Glue::UserDefinedFunction",
                "Properties": {
                    "DatabaseName": {"Ref": "Db"},
                    "FunctionName": fn_name,
                    "ClassName": class_name,
                    "OwnerType": "USER",
                    "OwnerName": owner_name,
                },
            },
        },
        "Outputs": {
            "DqRef": {"Value": {"Ref": "Dq"}},
            "UdfRef": {"Value": {"Ref": "Udf"}},
        },
    })

    template_doc = json.loads(template)
    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    def own_rulesets():
        return [r["Name"] for r in _pages(glue.list_data_quality_rulesets, "Rulesets")
                if r["Name"] == dq_name]

    def own_functions():
        return paginate(glue, "get_user_defined_functions", "UserDefinedFunctions",
                        DatabaseName=db_name, Pattern=fn_name)

    # Ruleset Ref (its Name) against an independent ListDataQualityRulesets.
    assert (outputs["DqRef"], own_rulesets()) == (dq_name, [dq_name]), (
        f"Ref {outputs['DqRef']!r}, ListDataQualityRulesets {own_rulesets()!r}"
    )
    dq = glue.get_data_quality_ruleset(Name=dq_name)
    got_dq = (dq["Name"], dq["Ruleset"], dq["TargetTable"])
    assert got_dq == (dq_name, ruleset_dqdl, {"TableName": tbl_name, "DatabaseName": db_name}), (
        f"GetDataQualityRuleset {got_dq!r}"
    )
    # Function Ref (its ARN) against the database's own function listing.
    partition = stack_id.split(":")[1]
    expected_arn = (f"arn:{partition}:glue:{ctx.region}:{ctx.account}:userDefinedFunction/"
                    f"{db_name}/{fn_name}")
    got_udf = [(u["FunctionName"], u["ClassName"], u["OwnerType"], u["OwnerName"])
               for u in own_functions()]
    assert (outputs["UdfRef"], got_udf) == (expected_arn, [(fn_name, class_name, "USER",
                                                            owner_name)]), (
        f"Ref {outputs['UdfRef']!r}, GetUserDefinedFunctions {got_udf!r}"
    )

    # The children alone: an update dropping the ruleset and function leaves the table.
    for key in ("Dq", "Udf"):
        del template_doc["Resources"][key]
    template_doc["Outputs"] = {"TblRef": {"Value": {"Ref": "Tbl"}}}
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_doc))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    not_found = (
        "EntityNotFoundException",
        f"Cannot find Data Quality Ruleset in account {ctx.account} with name {dq_name}"
    )
    expect_error(lambda: glue.get_data_quality_ruleset(Name=dq_name), *not_found)
    assert own_rulesets() == [], f"the dropped ruleset is listed: {own_rulesets()!r}"
    assert own_functions() == [], f"the dropped function is listed: {own_functions()!r}"
    kept = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["Name"]
    assert kept == tbl_name, f"the table after the update reads {kept!r}"

    delete_stack(cfn, stack_id)
    not_found_2 = ("EntityNotFoundException", f"Database {db_name} not found.")
    expect_error(lambda: glue.get_database(Name=db_name), *not_found_2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
