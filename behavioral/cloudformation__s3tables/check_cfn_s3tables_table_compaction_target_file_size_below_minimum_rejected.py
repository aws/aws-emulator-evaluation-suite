"""cfn-s3tables-table-compaction-target-file-size-below-minimum-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-s3tables-table-compaction-target-file-size-below-minimum-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

def _template(bucket_name: str, ns_name: str, table_name: str, target_file_size_mb: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TableBucket": {
                "Type": "AWS::S3Tables::TableBucket",
                "Properties": {"TableBucketName": bucket_name},
            },
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
                    "Compaction": {"Status": "enabled", "TargetFileSizeMB": target_file_size_mb},
                },
            },
        },
        "Outputs": {
            "TableBucketArn": {"Value": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]}},
            "TableArn": {"Value": {"Fn::GetAtt": ["Table", "TableARN"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation S3 Tables table with Compaction.TargetFileSizeMB under 64 fails validation.

    No table bucket is created, while the same template at 64 deploys with that compaction setting.
    """
    cf = ctx.client("cloudformation")
    s3tables = ctx.client("s3tables")
    tok = ctx.unique_name("sim2real-cfn-s3tcompact-")
    good_bucket = f"{tok}-good-bkt"
    bad_bucket = f"{tok}-bad-bkt"
    ns_name = tok.replace("-", "_")
    table_name = f"{ns_name}_table"

    # Positive control: same template, the one property at a VALID value (the schema minimum).
    good_id = create_stack(ctx, cf, f"{tok}-good", _template(good_bucket, ns_name, table_name, 64))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cf, good_id)
    tables = paginate(s3tables, "list_tables", "tables", tableBucketARN=out["TableBucketArn"])
    assert [(t["name"], t["tableARN"]) for t in tables] == [(table_name, out["TableArn"])], (
        f"ListTables in the control bucket found {tables!r}"
    )
    config = s3tables.get_table_maintenance_configuration(
        tableBucketARN=out["TableBucketArn"], namespace=ns_name, name=table_name,
    )["configuration"]["icebergCompaction"]
    got = (config["status"], config["settings"]["icebergCompaction"]["targetFileSizeMB"])
    assert got == ("enabled", 64), f"control table compaction reads {config!r}"

    # The same template with TargetFileSizeMB 32, refused before anything is provisioned.
    bad_id = create_stack(ctx, cf, f"{tok}-bad", _template(bad_bucket, ns_name, table_name, 32))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    want = [("Table", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "#/Compaction/TargetFileSizeMB: 32 is not greater or equal to 64",
             "/Resources/Table/Properties/Compaction/TargetFileSizeMB")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through S3 Tables, by the bucket name the rejected stack declared.
    listed = [b for b in paginate(s3tables, "list_table_buckets", "tableBuckets", prefix=bad_bucket)
              if b["name"] == bad_bucket]
    assert listed == [], f"the rejected stack's table bucket is listed: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
