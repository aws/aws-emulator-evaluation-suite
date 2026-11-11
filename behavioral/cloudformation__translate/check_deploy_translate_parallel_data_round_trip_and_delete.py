"""deploy-translate-parallel-data-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-translate-parallel-data-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "translate"]

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

_CSV = "en,es\nconference room,sala de reuniones\n"
_NOT_FOUND = ("ResourceNotFoundException", "INVALID_REQUEST: Parallel Data does not exist.")


def _template(name: str, bucket: str, key: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pd": {
                "Type": "AWS::Translate::ParallelData",
                "Properties": {
                    "Name": name,
                    "Description": "sim2real parallel data round trip",
                    "ParallelDataConfig": {"S3Uri": f"s3://{bucket}/{key}", "Format": "CSV"},
                    "Tags": [{"Key": "sim2real-pd", "Value": name}],
                },
            }
        },
        "Outputs": {
            "PdArn": {"Value": {"Ref": "Pd"}},
            "Status": {"Value": {"Fn::GetAtt": "Pd.Status"}},
            "SourceLanguageCode": {"Value": {"Fn::GetAtt": "Pd.SourceLanguageCode"}},
            "TargetLanguageCodes": {
                "Value": {"Fn::Join": [",", {"Fn::GetAtt": "Pd.TargetLanguageCodes"}]}
            },
        },
    })


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _bucket(ctx, s3, prefix: str) -> str:
    """A tagged setup bucket for the CSV input, removed after the stacks that read it."""
    bucket = ctx.unique_name(prefix)
    # us-east-1 is S3's default location and refuses an explicit LocationConstraint naming it.
    bucket_kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        bucket_kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_kw)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    return bucket


def _all_parallel_data(translate) -> list:
    """Every ListParallelData entry, paged by hand: the operation has no botocore paginator."""
    rows, kw = [], {}
    while True:
        page = translate.list_parallel_data(**kw)
        rows += page["ParallelDataPropertiesList"]
        if not page.get("NextToken"):
            return rows
        kw = {"NextToken": page["NextToken"]}


def _own_tags(translate, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Translate::ParallelData imports its S3 CSV to Status 'ACTIVE', and
    Translate shows the Ref ARN it lists by name, the declared S3Uri/Format/Description/tags and the
    derived read-only attributes; deleting the stack removes it from GetParallelData.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-translate-paralleldata.html
    """
    s3 = ctx.client("s3")
    translate = ctx.client("translate")
    cfn = ctx.client("cloudformation")
    bucket = _bucket(ctx, s3, "sim2real-pdbkt-")
    key = "parallel-data/input.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=_CSV.encode())
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))

    name = ctx.unique_name("sim2real-pd-")
    stack = ctx.unique_name("sim2real-pdstack-")
    stack_id = create_stack(ctx, cfn, stack, _template(name, bucket, key))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    listed = [p["Arn"] for p in _all_parallel_data(translate) if p["Name"] == name]
    assert listed == [outputs["PdArn"]], f"ListParallelData by name {listed!r}, Ref {outputs['PdArn']!r}"

    got = translate.get_parallel_data(Name=name)["ParallelDataProperties"]
    read = (got["Arn"], got["Status"], got["SourceLanguageCode"], ",".join(got["TargetLanguageCodes"]))
    assert read == (outputs["PdArn"], outputs["Status"], outputs["SourceLanguageCode"],
                    outputs["TargetLanguageCodes"]), f"GetParallelData {read!r}, GetAtts {outputs!r}"
    read = (got["Status"], got["ParallelDataConfig"], got["Description"],
            got["ImportedRecordCount"])
    want = ("ACTIVE", {"S3Uri": f"s3://{bucket}/{key}", "Format": "CSV"},
            "sim2real parallel data round trip", 1)
    assert read == want, f"parallel data reads {read!r}, expected {want!r}"
    pd_tags = _own_tags(translate, got["Arn"])
    assert pd_tags == {"sim2real": stack, "sim2real-pd": name}, f"tags {pd_tags!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: translate.get_parallel_data(Name=name), *_NOT_FOUND)
    names_after = [p["Name"] for p in _all_parallel_data(translate)]
    assert name not in names_after, f"ListParallelData still includes deleted {name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
