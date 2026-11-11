"""deploy-glue-ml-transform-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-ml-transform-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "iam"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_GLUE_POLICY = "service-role/AWSGlueServiceRole"


def _pages(fn, key, **kw):
    """Every item under ``key`` across all NextToken pages of ``fn`` (no botocore paginator)."""
    items, token = [], None
    while True:
        page = fn(**kw, **({"NextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return items


def _template(role_name, db_name, tbl_name, mlt_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "glue.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::aws:policy/{_GLUE_POLICY}"},
                    ],
                },
            },
            "Db": {
                "Type": "AWS::Glue::Database",
                "Properties": {"CatalogId": {"Ref": "AWS::AccountId"},
                               "DatabaseInput": {"Name": db_name}},
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
                            "Location": f"s3://{tbl_name.replace('_', '-')}/data/",
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat":
                                "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary":
                                    "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                            },
                        },
                    },
                },
            },
            "Mlt": {
                "Type": "AWS::Glue::MLTransform",
                "Properties": {
                    "Name": mlt_name,
                    "Role": {"Ref": "Role"},
                    "InputRecordTables": {
                        "GlueTables": [{"DatabaseName": {"Ref": "Db"},
                                        "TableName": {"Ref": "Tbl"}}],
                    },
                    "TransformParameters": {
                        "TransformType": "FIND_MATCHES",
                        "FindMatchesParameters": {"PrimaryKeyColumnName": "id"},
                    },
                    "Tags": {"sim2real-mlt": mlt_name},
                },
            },
        },
        "Outputs": {"MltRef": {"Value": {"Ref": "Mlt"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue MLTransform reads back through Glue and IAM, then goes with its stack.

    Ref is the TransformId Glue lists under the declared name; the name, role, input table,
    FIND_MATCHES parameters and tags read back; deleting the stack removes the transform.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    stack = ctx.unique_name("sim2real-cfngluemlt-")
    role_name = ctx.unique_name("sim2real-cfngluemlt-role-")
    db_name = ctx.unique_name("sim2real_cfngluemlt_db_").replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_cfngluemlt_tbl_").replace("-", "_")
    mlt_name = ctx.unique_name("sim2real-cfngluemlt-mlt-")

    stack_id = create_stack(ctx, cfn, stack, _template(role_name, db_name, tbl_name, mlt_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    transform_id = stack_outputs(cfn, stack_id)["MltRef"]

    # Ref against an independent read: the transforms Glue lists under the declared name.
    listed = _pages(glue.get_ml_transforms, "Transforms", Filter={"Name": mlt_name})
    assert [t["TransformId"] for t in listed] == [transform_id], (
        f"GetMLTransforms(Name={mlt_name!r}) lists {listed!r} for Ref {transform_id!r}"
    )
    mlt = listed[0]
    got = (mlt["Name"], mlt["Role"], mlt["InputRecordTables"], mlt["Parameters"])
    want = (mlt_name, role_name, [{"DatabaseName": db_name, "TableName": tbl_name}],
            {"TransformType": "FIND_MATCHES", "FindMatchesParameters": {"PrimaryKeyColumnName": "id"}})
    assert got == want, f"transform (Name, Role, InputRecordTables, Parameters) {got!r}"

    arn = f"arn:{partition}:glue:{ctx.region}:{ctx.account}:mlTransform/{transform_id}"
    mlt_tags = {k: v for k, v in glue.get_tags(ResourceArn=arn)["Tags"].items()
                if not k.startswith("aws:")}
    assert mlt_tags == {"sim2real": stack, "sim2real-mlt": mlt_name}, f"tags {mlt_tags!r}"

    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }], f"role trust {role['AssumeRolePolicyDocument']!r}"
    attached = [p["PolicyArn"] for p in paginate(iam, "list_attached_role_policies",
                                                 "AttachedPolicies", RoleName=role_name)]
    assert attached == [f"arn:{partition}:iam::aws:policy/{_GLUE_POLICY}"], (
        f"role managed policies {attached!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: glue.get_ml_transform(TransformId=transform_id))
    gone = ("EntityNotFoundException",
            f"Cannot find MLTransform in account {ctx.account} with handle {transform_id}")
    expect_error(lambda: glue.get_ml_transform(TransformId=transform_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
