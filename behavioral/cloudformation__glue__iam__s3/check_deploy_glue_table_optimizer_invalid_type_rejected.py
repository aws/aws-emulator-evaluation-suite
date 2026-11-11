"""deploy-glue-table-optimizer-invalid-type-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-table-optimizer-invalid-type-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "iam", "s3"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


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

_BAD_TYPE = "not_a_real_optimizer_type"
_REJECTED = (
    f"1 validation error detected: Value '{_BAD_TYPE}' at 'type' failed to satisfy constraint: "
    "Member must satisfy enum value set: [compaction, orphan_file_deletion, retention] (Service: "
    "Glue, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_DB_ARN = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${Db}"
_TBL_ARN = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/${Db}/*"
_CATALOG_ARN = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog"


def _template(db_name, tbl_name, bucket_name, optimizer_type, with_optimizer=True):
    resources = {
        "Bucket": {
            "Type": "AWS::S3::Bucket", "DeletionPolicy": "Delete",
            "Properties": {"BucketName": bucket_name},
        },
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "sim2real-topt-access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                           "s3:ListBucket"],
                                "Resource": [
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"},
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["glue:GetTable", "glue:UpdateTable",
                                           "glue:GetPartitions", "glue:BatchDeletePartition"],
                                "Resource": [{"Fn::Sub": _CATALOG_ARN}, {"Fn::Sub": _DB_ARN},
                                             {"Fn::Sub": _TBL_ARN}],
                            },
                        ],
                    },
                }],
            },
        },
        "Db": {
            "Type": "AWS::Glue::Database",
            "Properties": {"CatalogId": {"Ref": "AWS::AccountId"},
                           "DatabaseInput": {"Name": db_name}},
        },
        "Tbl": {
            "Type": "AWS::Glue::Table", "DeletionPolicy": "Delete",
            "Properties": {
                "CatalogId": {"Ref": "AWS::AccountId"},
                "DatabaseName": {"Ref": "Db"},
                "Name": tbl_name,
                "OpenTableFormatInput": {
                    "IcebergInput": {
                        "MetadataOperation": "CREATE", "Version": "2",
                        "IcebergTableInput": {
                            "Location": {"Fn::Sub": "s3://${Bucket}/data/"},
                            "Schema": {
                                "SchemaId": 0, "Type": "struct",
                                "Fields": [{"Id": 1, "Name": "id", "Type": "int",
                                            "Required": True}],
                            },
                        },
                    },
                },
            },
        },
    }
    outputs = {"RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}}}
    if with_optimizer:
        resources["Topt"] = {
            "Type": "AWS::Glue::TableOptimizer",
            "Properties": {
                "CatalogId": {"Ref": "AWS::AccountId"},
                "DatabaseName": {"Ref": "Db"},
                "TableName": {"Ref": "Tbl"},
                "Type": optimizer_type,
                "TableOptimizerConfiguration": {
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}, "Enabled": True,
                },
            },
        }
        outputs["ToptRef"] = {"Value": {"Ref": "Topt"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _empty_bucket(s3, bucket):
    """Delete every object, so the stack's own bucket delete does not fail; a gone bucket is done."""
    try:
        keys = [o["Key"] for o in paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for i in range(0, len(keys), 1000):
        s3.delete_objects(Bucket=bucket,
                          Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]]})


def _delete_retaining(cf, stack_id, logical_id):
    """Delete a stack whose ``logical_id`` never existed and whose delete handler fails again.

    The first delete must end DELETE_FAILED on that resource alone; the retry retains it.
    """
    wait_stack(cf, stack_id)
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status == "DELETE_FAILED":
        cf.delete_stack(StackName=stack_id, RetainResources=[logical_id])
        status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue TableOptimizer with a Type outside Glue's enum fails CREATE.

    Glue refuses it naming the enum and re-refuses on rollback (ROLLBACK_FAILED, table kept with
    no optimizer), while Type compaction deploys an optimizer read back with role and Enabled.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    names = {k: (ctx.unique_name(f"sim2real_cfntoptbad_db_{k}_").replace("-", "_"),
                 ctx.unique_name(f"sim2real_cfntoptbad_tbl_{k}_").replace("-", "_"),
                 ctx.unique_name(f"sim2real-cfntoptbad-{k}-").lower()) for k in ("ok", "bad")}

    # Positive control: the same template, the one property given a VALID value.
    ok_db, ok_tbl, ok_bucket = names["ok"]
    ok_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfntoptbad-okstack-"),
                         _template(ok_db, ok_tbl, ok_bucket, "compaction"),
                         Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _empty_bucket(s3, ok_bucket))
    bad_db, bad_tbl, bad_bucket = names["bad"]
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfntoptbad-badstack-"),
                          _template(bad_db, bad_tbl, bad_bucket, _BAD_TYPE),
                          Capabilities=["CAPABILITY_IAM"])
    # Rollback calls the rejected optimizer's delete, which re-validates Type and fails, so the
    # stack ends ROLLBACK_FAILED; its delete retains that optimizer, which never existed.
    ctx.on_cleanup(lambda: _delete_retaining(cfn, bad_id, "Topt"))
    ctx.on_cleanup(lambda: _empty_bucket(s3, bad_bucket))

    status = wait_stack(cfn, ok_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, ok_id))!r}"
    )
    out = stack_outputs(cfn, ok_id)
    role_arn = iam.get_role(RoleName=out["RoleArn"].rsplit("/", 1)[1])["Role"]["Arn"]
    got = glue.get_table_optimizer(CatalogId=ctx.account, DatabaseName=ok_db, TableName=ok_tbl,
                                   Type="compaction")
    opt = got["TableOptimizer"]
    assert (out["ToptRef"], opt["type"], opt["configuration"]["roleArn"],
            opt["configuration"]["enabled"]) == (
        f"{ok_tbl}|{ok_db}|compaction|{ctx.account}", "compaction", role_arn, True), (
        f"control optimizer {got!r}, Ref {out['ToptRef']!r}"
    )

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_FAILED", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Topt")
    got = handler_reason(reason, ctx.account, bad_db, bad_tbl)
    assert got == _REJECTED, f"Topt reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Glue, BEFORE this check deletes: the kept table has no optimizer.
    no_optimizer = (
        "EntityNotFoundException",
        f"No optimizer of type compaction found for the table: {bad_tbl} (Service: glue; "
        "Status Code: 404; Error Code: EntityNotFoundException; Request ID: <id>; Proxy: null)",
    )
    _expect_masked(ctx, lambda: glue.get_table_optimizer(
        CatalogId=ctx.account, DatabaseName=bad_db, TableName=bad_tbl, Type="compaction"),
        *no_optimizer)


def _expect_masked(ctx, fn, code, message):
    """Assert ``fn()`` raises ``code`` with ``message`` once its request ids are masked."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], masked(exc.response["Error"]["Message"], ctx.account))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
