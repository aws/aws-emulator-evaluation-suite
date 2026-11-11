"""deploy-glue-ml-transform-invalid-primary-key-column-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-glue-ml-transform-invalid-primary-key-column-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----


_REQUEST_TOKEN_RE = re.compile(r"RequestToken: [0-9a-f-]+")


def _template(db_name: str, tbl_name: str, primary_key_column: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "glue.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                                      "service-role/AWSGlueServiceRole"}],
                },
            },
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
                            "Columns": [
                                {"Name": "id", "Type": "string"},
                                {"Name": "name", "Type": "string"},
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
            "Mlt": {
                "Type": "AWS::Glue::MLTransform",
                "Properties": {
                    "Role": {"Ref": "Role"},
                    "InputRecordTables": {
                        "GlueTables": [{"DatabaseName": {"Ref": "Db"}, "TableName": {"Ref": "Tbl"}}],
                    },
                    "TransformParameters": {
                        "TransformType": "FIND_MATCHES",
                        "FindMatchesParameters": {"PrimaryKeyColumnName": primary_key_column},
                    },
                },
            },
        },
        "Outputs": {"MltRef": {"Value": {"Ref": "Mlt"}}},
    })


_REJECTED = (
    "Schema should contain given primary key: not_a_real_column (Service: Glue, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _transforms_on(glue, db, tbl):
    """Every ML transform reading ``db``.``tbl``; GetMLTransforms has no botocore paginator."""
    found, token = [], None
    while True:
        page = glue.get_ml_transforms(**({"NextToken": token} if token else {}))
        found.extend(t for t in page["Transforms"]
                     if {"DatabaseName": db, "TableName": tbl} in t["InputRecordTables"])
        token = page.get("NextToken")
        if not token:
            return found


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue ML transform naming a primary key absent from its table is refused.

    Glue's reason names the column and no transform reads the table, while the same template
    naming a real column deploys.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    db_a = ctx.unique_name("sim2real_behav_mlbaddb_a_").replace("-", "_")
    tbl_a = ctx.unique_name("sim2real_behav_mlbadtbl_a_").replace("-", "_")
    db_b = ctx.unique_name("sim2real_behav_mlbaddb_b_").replace("-", "_")
    tbl_b = ctx.unique_name("sim2real_behav_mlbadtbl_b_").replace("-", "_")
    stack_a = ctx.unique_name("sim2real-behav-cfn-gluemltbad-a-")
    stack_b = ctx.unique_name("sim2real-behav-cfn-gluemltbad-b-")

    # Positive control: the same template, PrimaryKeyColumnName naming a real column.
    stack_a_id = create_stack(ctx, cfn, stack_a, _template(db_a, tbl_a, "id"),
                              Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_a_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    transform_id = stack_outputs(cfn, stack_a_id)["MltRef"]
    control = [(t["TransformId"], t["Parameters"]["FindMatchesParameters"]["PrimaryKeyColumnName"])
               for t in _transforms_on(glue, db_a, tbl_a)]
    assert control == [(transform_id, "id")], f"control transforms {control!r}"

    # The one bad property: PrimaryKeyColumnName names a column the table lacks.
    stack_b_id = create_stack(ctx, cfn, stack_b, _template(db_b, tbl_b, "not_a_real_column"),
                              Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_b_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, stack_b_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    got = handler_reason(failed_reason(stack_events(cfn, stack_b_id), "Mlt"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Glue: no transform reads this run's table, BEFORE the delete.
    left = _transforms_on(glue, db_b, tbl_b)
    assert left == [], f"a transform on the rejected stack's table is listed: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
