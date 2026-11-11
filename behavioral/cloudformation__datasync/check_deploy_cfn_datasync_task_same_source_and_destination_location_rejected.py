"""deploy-cfn-datasync-task-same-source-and-destination-location-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-datasync-task-same-source-and-destination-location-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "datasync"]

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

_REJECTED = (
    "Invalid request provided: Destination location cannot be same as source location. "
    "(Service: DataSync, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)

_S3_BUCKET_ACTIONS = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]
_S3_OBJECT_ACTIONS = [
    "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:GetObjectTagging",
    "s3:GetObjectVersion", "s3:GetObjectVersionTagging", "s3:ListMultipartUploadParts",
    "s3:PutObject", "s3:PutObjectTagging",
]


def _template(dest_ref: str, task_name: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "datasync.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    buckets = [{"Fn::GetAtt": ["SrcBucket", "Arn"]}, {"Fn::GetAtt": ["DstBucket", "Arn"]}]
    objects = [{"Fn::Sub": "${SrcBucket.Arn}/*"}, {"Fn::Sub": "${DstBucket.Arn}/*"}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SrcBucket": {"Type": "AWS::S3::Bucket"},
            "DstBucket": {"Type": "AWS::S3::Bucket"},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [{
                        "PolicyName": "access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": _S3_BUCKET_ACTIONS,
                                 "Resource": buckets},
                                {"Effect": "Allow", "Action": _S3_OBJECT_ACTIONS,
                                 "Resource": objects},
                            ],
                        },
                    }],
                },
            },
            "SrcLoc": {
                "Type": "AWS::DataSync::LocationS3",
                "Properties": {
                    "S3BucketArn": {"Fn::GetAtt": ["SrcBucket", "Arn"]},
                    "S3Config": {"BucketAccessRoleArn": {"Fn::GetAtt": ["Role", "Arn"]}},
                },
                "DependsOn": "Role",
            },
            "DstLoc": {
                "Type": "AWS::DataSync::LocationS3",
                "Properties": {
                    "S3BucketArn": {"Fn::GetAtt": ["DstBucket", "Arn"]},
                    "S3Config": {"BucketAccessRoleArn": {"Fn::GetAtt": ["Role", "Arn"]}},
                },
                "DependsOn": "Role",
            },
            "Task": {
                "Type": "AWS::DataSync::Task",
                "Properties": {
                    "Name": task_name,
                    "SourceLocationArn": {"Ref": "SrcLoc"},
                    "DestinationLocationArn": {"Ref": dest_ref},
                },
            },
        },
        "Outputs": {
            "SrcBucketName": {"Value": {"Ref": "SrcBucket"}},
            "DstBucketName": {"Value": {"Ref": "DstBucket"}},
            "SrcLocArn": {"Value": {"Ref": "SrcLoc"}},
            "DstLocArn": {"Value": {"Ref": "DstLoc"}},
            "TaskArn": {"Value": {"Ref": "Task"}},
        },
    })


def _location_arns_for_uri(ds, uri: str) -> list[str]:
    """Every listed location ARN whose LocationUri is ``uri``, read across all pages."""
    return [loc["LocationArn"]
            for page in ds.get_paginator("list_locations").paginate()
            for loc in page["Locations"] if loc["LocationUri"] == uri]


def _task_arns_named(ds, name: str) -> list[str]:
    """Every listed task ARN whose Name is ``name``, read across all pages."""
    return [t["TaskArn"]
            for page in ds.get_paginator("list_tasks").paginate()
            for t in page["Tasks"] if t.get("Name") == name]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DataSync::Task whose DestinationLocationArn repeats its own
    SourceLocationArn is rejected by DataSync, and the rollback removes both valid locations;
    the same template with a distinct destination deploys a task DataSync reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-task.html
    """
    cfn = ctx.client("cloudformation")
    ds = ctx.client("datasync")

    # Both stacks deploy side by side; only DestinationLocationArn (and the task's name) differ.
    good_stack = ctx.unique_name("sim2real-ds-badtask-ctl-")
    good_task_name = ctx.unique_name("sim2real-ds-badtask-ctl-task-")
    good_id = create_stack(ctx, cfn, good_stack, _template("DstLoc", good_task_name),
                           Capabilities=["CAPABILITY_IAM"])
    bad_stack = ctx.unique_name("sim2real-ds-badtask-neg-")
    bad_task_name = ctx.unique_name("sim2real-ds-badtask-neg-task-")
    bad_id = create_stack(ctx, cfn, bad_stack, _template("SrcLoc", bad_task_name),
                          Capabilities=["CAPABILITY_IAM"])

    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_outputs = stack_outputs(cfn, good_id)
    good_task_arns = _task_arns_named(ds, good_task_name)
    assert good_task_arns == [good_outputs["TaskArn"]], (
        f"expected ListTasks to hold exactly the control task Ref under its name, "
        f"got {len(good_task_arns)} match(es) {good_task_arns!r}"
    )
    good_src_arns = _location_arns_for_uri(ds, f"s3://{good_outputs['SrcBucketName']}/")
    assert good_src_arns == [good_outputs["SrcLocArn"]], (
        f"expected ListLocations to hold exactly the control SrcLoc Ref for its bucket, "
        f"got {good_src_arns!r}"
    )
    good_dst_arns = _location_arns_for_uri(ds, f"s3://{good_outputs['DstBucketName']}/")
    assert good_dst_arns == [good_outputs["DstLocArn"]], (
        f"expected ListLocations to hold exactly the control DstLoc Ref for its bucket, "
        f"got {good_dst_arns!r}"
    )
    good_task = ds.describe_task(TaskArn=good_outputs["TaskArn"])
    got = (good_task["Name"], good_task["SourceLocationArn"], good_task["DestinationLocationArn"])
    want = (good_task_name, good_outputs["SrcLocArn"], good_outputs["DstLocArn"])
    assert got == want, f"control task (Name, Source, Destination) is {got!r}, expected {want!r}"

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with a self-referential task ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    reason = handler_reason(failed_reason(stack_events(cfn, bad_id), "Task"), ctx.account)
    assert reason == _REJECTED, f"Task failure reason {reason!r}, expected {_REJECTED!r}"

    bad_task_arns = _task_arns_named(ds, bad_task_name)
    assert bad_task_arns == [], (
        f"expected no task named like the rejected one, ListTasks holds {len(bad_task_arns)}"
    )

    bad_resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    by_logical = {r["LogicalResourceId"]: r for r in bad_resources}
    for logical_id in ("SrcLoc", "DstLoc"):
        loc_arn = by_logical[logical_id]["PhysicalResourceId"]
        location_gone = ("InvalidRequestException", f"Location {loc_arn} is not found.")
        expect_error(lambda arn=loc_arn: ds.describe_location_s3(LocationArn=arn), *location_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
