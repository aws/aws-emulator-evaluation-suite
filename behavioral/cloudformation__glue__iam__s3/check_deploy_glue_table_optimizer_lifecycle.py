"""deploy-glue-table-optimizer-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-table-optimizer-lifecycle"
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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

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


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Glue TableOptimizer on an Iceberg table reads back through Glue and IAM.

    Ref is the documented composite identifier and the role and Enabled flag read back; an update
    dropping the optimizer removes it while its table answers, and deleting the stack removes both.
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-cfngluetopt-")
    db_name = ctx.unique_name("sim2real_cfngluetopt_db_").replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_cfngluetopt_tbl_").replace("-", "_")
    bucket = ctx.unique_name("sim2real-cfngluetopt-").lower()

    stack_id = create_stack(ctx, cfn, stack, _template(db_name, tbl_name, bucket, "compaction"),
                            Capabilities=["CAPABILITY_IAM"])
    # The Iceberg table writes its metadata into the bucket: empty it before the stack deletes.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert out["ToptRef"] == f"{tbl_name}|{db_name}|compaction|{ctx.account}", (
        f"Ref(Topt) {out['ToptRef']!r}"
    )
    role_arn = iam.get_role(RoleName=out["RoleArn"].rsplit("/", 1)[1])["Role"]["Arn"]
    assert out["RoleArn"] == role_arn, f"GetAtt Role.Arn {out['RoleArn']!r}, IAM {role_arn!r}"

    def read():
        return glue.get_table_optimizer(CatalogId=ctx.account, DatabaseName=db_name,
                                        TableName=tbl_name, Type="compaction")

    got = read()
    opt = got["TableOptimizer"]
    assert (got["CatalogId"], got["DatabaseName"], got["TableName"], opt["type"],
            opt["configuration"]["roleArn"], opt["configuration"]["enabled"]) == (
        ctx.account, db_name, tbl_name, "compaction", role_arn, True), f"optimizer {got!r}"

    # Child before parent: the update drops only the optimizer while its table still answers.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"],
                     TemplateBody=_template(db_name, tbl_name, bucket, "compaction",
                                            with_optimizer=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"optimizer-removing update ended {status!r}"
    table = glue.get_table(CatalogId=ctx.account, DatabaseName=db_name, Name=tbl_name)["Table"]
    assert (table["DatabaseName"], table["Name"]) == (db_name, tbl_name), f"table {table!r}"
    gone = ("EntityNotFoundException",
            f"No optimizer of type compaction found for the table: {tbl_name} (Service: glue; "
            "Status Code: 404; Error Code: EntityNotFoundException; Request ID: <id>; Proxy: null)")
    _expect_masked(ctx, read, *gone)

    _empty_bucket(s3, bucket)
    delete_stack(cfn, stack_id)
    gone = ("EntityNotFoundException",
            "Entity Not Found (Service: AmazonDataCatalog; Status Code: 400; Error Code: "
            "EntityNotFoundException; Request ID: <id>; Proxy: null) (Service: glue; Status Code: "
            "404; Error Code: EntityNotFoundException; Request ID: <id>; Proxy: null)")
    _expect_masked(ctx, read, *gone)


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
