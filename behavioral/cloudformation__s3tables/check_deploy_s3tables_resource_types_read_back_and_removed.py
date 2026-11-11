"""deploy-s3tables-resource-types-read-back-and-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3tables-resource-types-read-back-and-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3tables"]

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

_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}


def _policy(principal, action, sid):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Allow", "Principal": {"AWS": principal},
                       "Action": action, "Resource": "*"}],
    }


def _template(bucket_name, ns_name, table_name, with_table=True):
    resources = {
        "TableBucket": {
            "Type": "AWS::S3Tables::TableBucket",
            "Properties": {"TableBucketName": bucket_name},
        },
        "TableBucketPolicy": {
            "Type": "AWS::S3Tables::TableBucketPolicy",
            "Properties": {
                "TableBucketARN": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]},
                "ResourcePolicy": _policy(_ROOT, "s3tables:GetTableBucket",
                                          "SimParityAllowGetBucket"),
            },
        },
    }
    outputs = {
        "TableBucketRef": {"Value": {"Ref": "TableBucket"}},
        "TableBucketArn": {"Value": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]}},
        "TableBucketPolicyRef": {"Value": {"Ref": "TableBucketPolicy"}},
    }
    if with_table:
        resources.update({
            "Namespace": {
                "Type": "AWS::S3Tables::Namespace",
                "Properties": {
                    "TableBucketARN": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]},
                    "Namespace": ns_name,
                },
            },
            "Table": {
                "Type": "AWS::S3Tables::Table",
                "DependsOn": "Namespace",
                "Properties": {
                    "TableBucketARN": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]},
                    "Namespace": ns_name,
                    "TableName": table_name,
                    "OpenTableFormat": "ICEBERG",
                    "WithoutMetadata": "Yes",
                },
            },
            "TablePolicy": {
                "Type": "AWS::S3Tables::TablePolicy",
                "Properties": {
                    "TableARN": {"Fn::GetAtt": ["Table", "TableARN"]},
                    "ResourcePolicy": _policy(_ROOT, "s3tables:GetTable", "SimParityAllowGetTable"),
                },
            },
        })
        outputs.update({
            "NamespaceRef": {"Value": {"Ref": "Namespace"}},
            "TableRef": {"Value": {"Ref": "Table"}},
            "TableArn": {"Value": {"Fn::GetAtt": ["Table", "TableARN"]}},
            "TableWarehouseLocation": {"Value": {"Fn::GetAtt": ["Table", "WarehouseLocation"]}},
            "TableVersionToken": {"Value": {"Fn::GetAtt": ["Table", "VersionToken"]}},
            "TablePolicyRef": {"Value": {"Ref": "TablePolicy"}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _tags(s3tables, arn):
    """The resource's tags without the ``aws:`` system tags."""
    tags_map = s3tables.list_tags_for_resource(resourceArn=arn).get("tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation S3 Tables bucket, namespace, table and both policies read back exactly.

    An update dropping the namespace, table and table policy empties the bucket's listings while
    the same bucket answers; the stack delete removes the bucket and its policy.
    """
    cf = ctx.client("cloudformation")
    s3tables = ctx.client("s3tables")
    stack = ctx.unique_name("sim2real-deploy-s3t-")
    bucket_name = ctx.unique_name("sim2real-deploy-s3t-bkt-")
    ns_name = ctx.unique_name("sim2real_deploy_s3t_ns_").replace("-", "_")
    table_name = ctx.unique_name("sim2real_deploy_s3t_tbl_").replace("-", "_")

    stack_id = create_stack(ctx, cf, stack, _template(bucket_name, ns_name, table_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    root = f"arn:{partition}:iam::{ctx.account}:root"
    bucket_arn = f"arn:{partition}:s3tables:{ctx.region}:{ctx.account}:bucket/{bucket_name}"

    # TableBucket: Ref and GetAtt == the ARN ListTableBuckets reports for the templated name.
    listed = [b for b in paginate(s3tables, "list_table_buckets", "tableBuckets",
                                  prefix=bucket_name) if b["name"] == bucket_name]
    assert [b["arn"] for b in listed] == [bucket_arn], f"ListTableBuckets found {listed!r}"
    assert (out["TableBucketRef"], out["TableBucketArn"]) == (bucket_arn, bucket_arn), (
        f"Ref {out['TableBucketRef']!r}, GetAtt {out['TableBucketArn']!r}, expected {bucket_arn!r}"
    )
    got_bucket = s3tables.get_table_bucket(tableBucketARN=bucket_arn)
    assert (got_bucket["arn"], got_bucket["name"]) == (bucket_arn, bucket_name), (
        f"GetTableBucket reads {got_bucket!r}"
    )
    bucket_tags = _tags(s3tables, bucket_arn)
    assert bucket_tags == {"sim2real": stack}, f"table bucket tags {bucket_tags!r}"
    bucket_created = got_bucket["createdAt"]

    # Namespace: Ref is "<bucketARN>|<namespace>"; ListNamespaces holds exactly the templated one.
    assert out["NamespaceRef"] == f"{bucket_arn}|{ns_name}", f"Ref {out['NamespaceRef']!r}"
    namespaces = paginate(s3tables, "list_namespaces", "namespaces", tableBucketARN=bucket_arn)
    assert [n["namespace"] for n in namespaces] == [[ns_name]], f"namespaces {namespaces!r}"

    # Table: Ref and GetAtt TableARN == the listed table's ARN; read-only GetAtts == GetTable.
    tables = paginate(s3tables, "list_tables", "tables", tableBucketARN=bucket_arn)
    assert [(t["name"], t["namespace"]) for t in tables] == [(table_name, [ns_name])], (
        f"ListTables found {tables!r}"
    )
    table_arn = tables[0]["tableARN"]
    assert (out["TableRef"], out["TableArn"]) == (table_arn, table_arn), (
        f"Ref {out['TableRef']!r}, GetAtt {out['TableArn']!r}, listed {table_arn!r}"
    )
    got_table = s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    got = (got_table["tableARN"], got_table["format"], got_table["warehouseLocation"],
           got_table["versionToken"])
    want = (table_arn, "ICEBERG", out["TableWarehouseLocation"], out["TableVersionToken"])
    assert got == want, f"GetTable reads {got!r}, expected {want!r}"
    table_tags = _tags(s3tables, table_arn)
    assert table_tags == {"sim2real": stack}, f"table tags {table_tags!r}"

    # Both policies: Ref == the parent's ARN, and the resource policy round-trips exactly.
    assert out["TableBucketPolicyRef"] == bucket_arn, f"Ref {out['TableBucketPolicyRef']!r}"
    got_bp = json.loads(
        s3tables.get_table_bucket_policy(tableBucketARN=bucket_arn)["resourcePolicy"])
    want_bp = _policy(root, "s3tables:GetTableBucket", "SimParityAllowGetBucket")
    assert got_bp == want_bp, f"table bucket policy {got_bp!r}, expected {want_bp!r}"
    assert out["TablePolicyRef"] == table_arn, f"TablePolicy Ref {out['TablePolicyRef']!r}"
    got_tp = json.loads(s3tables.get_table_policy(
        tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)["resourcePolicy"])
    want_tp = _policy(root, "s3tables:GetTable", "SimParityAllowGetTable")
    assert got_tp == want_tp, f"table policy {got_tp!r}, expected {want_tp!r}"

    # Children before the bucket: dropping the namespace, table and table policy empties the
    # bucket's listings while the same bucket (createdAt) still answers.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(bucket_name, ns_name, table_name, with_table=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    left_tables = paginate(s3tables, "list_tables", "tables", tableBucketARN=bucket_arn)
    assert left_tables == [], f"ListTables after the update: {left_tables!r}"
    left_ns = paginate(s3tables, "list_namespaces", "namespaces", tableBucketARN=bucket_arn)
    assert left_ns == [], f"ListNamespaces after the update: {left_ns!r}"
    gone = ("NotFoundException", "The specified table does not exist.")
    expect_error(lambda: s3tables.get_table_policy(
        tableBucketARN=bucket_arn, namespace=ns_name, name=table_name), *gone)
    still = s3tables.get_table_bucket(tableBucketARN=bucket_arn)
    assert still["createdAt"] == bucket_created, f"table bucket after the update: {still!r}"

    delete_stack(cf, stack_id)
    gone = ("NotFoundException", "The specified bucket does not exist.")
    expect_error(lambda: s3tables.get_table_bucket_policy(tableBucketARN=bucket_arn), *gone)
    expect_error(lambda: s3tables.get_table_bucket(tableBucketARN=bucket_arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
