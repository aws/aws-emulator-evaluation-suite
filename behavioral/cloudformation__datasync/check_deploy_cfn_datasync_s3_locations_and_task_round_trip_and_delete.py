"""deploy-cfn-datasync-s3-locations-and-task-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-datasync-s3-locations-and-task-round-trip-and-delete"
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


_S3_BUCKET_ACTIONS = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]
_S3_OBJECT_ACTIONS = [
    "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:GetObjectTagging",
    "s3:GetObjectVersion", "s3:GetObjectVersionTagging", "s3:ListMultipartUploadParts",
    "s3:PutObject", "s3:PutObjectTagging",
]
_ARN_HEAD = r"arn:aws[a-z-]*:datasync:{region}:{account}:"


def _template(task_name: str, *, with_task: bool = True) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "datasync.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    buckets = [{"Fn::GetAtt": ["SrcBucket", "Arn"]}, {"Fn::GetAtt": ["DstBucket", "Arn"]}]
    objects = [{"Fn::Sub": "${SrcBucket.Arn}/*"}, {"Fn::Sub": "${DstBucket.Arn}/*"}]
    resources = {
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
                            {"Effect": "Allow", "Action": _S3_BUCKET_ACTIONS, "Resource": buckets},
                            {"Effect": "Allow", "Action": _S3_OBJECT_ACTIONS, "Resource": objects},
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
    }
    outputs = {
        "SrcBucketName": {"Value": {"Ref": "SrcBucket"}},
        "DstBucketName": {"Value": {"Ref": "DstBucket"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        "SrcLocArn": {"Value": {"Ref": "SrcLoc"}},
        "DstLocArn": {"Value": {"Ref": "DstLoc"}},
        "SrcLocUri": {"Value": {"Fn::GetAtt": ["SrcLoc", "LocationUri"]}},
        "DstLocUri": {"Value": {"Fn::GetAtt": ["DstLoc", "LocationUri"]}},
    }
    if with_task:
        resources["Task"] = {
            "Type": "AWS::DataSync::Task",
            "Properties": {
                "Name": task_name,
                "SourceLocationArn": {"Ref": "SrcLoc"},
                "DestinationLocationArn": {"Ref": "DstLoc"},
            },
        }
        outputs["TaskArn"] = {"Value": {"Ref": "Task"}}
        outputs["TaskStatus"] = {"Value": {"Fn::GetAtt": ["Task", "Status"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
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


def _assert_location(ctx, ds, label: str, loc_arn: str, bucket: str, getatt_uri: str,
                     role_arn: str) -> None:
    """Ref is a documented location ARN listed for the bucket; DataSync echoes role and URI."""
    head = _ARN_HEAD.format(region=re.escape(ctx.region), account=ctx.account)
    assert re.fullmatch(head + r"location/loc-[0-9a-f]{17}", loc_arn), (
        f"Ref {label} {loc_arn!r} is not a DataSync location ARN in this account and region"
    )
    want_uri = f"s3://{bucket}/"
    listed = _location_arns_for_uri(ds, want_uri)
    assert listed == [loc_arn], (
        f"expected ListLocations to hold exactly Ref {label} for {want_uri!r}, got {listed!r}"
    )
    loc = ds.describe_location_s3(LocationArn=loc_arn)
    got = (loc["LocationUri"], loc["S3Config"]["BucketAccessRoleArn"])
    assert got == (want_uri, role_arn), (
        f"{label} DescribeLocationS3 (LocationUri, BucketAccessRoleArn) is {got!r}, "
        f"expected {(want_uri, role_arn)!r}"
    )
    assert getatt_uri == want_uri, (
        f"Fn::GetAtt {label}.LocationUri is {getatt_uri!r}, expected {want_uri!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DataSync::LocationS3 pair and AWS::DataSync::Task read back through
    DataSync with the template's buckets, role, name and wiring; a stack update removing the task
    deletes it while its locations stay, and deleting the stack removes the locations.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-locations3.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-task.html
    """
    cfn = ctx.client("cloudformation")
    ds = ctx.client("datasync")

    stack = ctx.unique_name("sim2real-ds-s3task-")
    task_name = ctx.unique_name("sim2real-ds-s3task-task-")

    stack_id = create_stack(ctx, cfn, stack, _template(task_name), Capabilities=["CAPABILITY_IAM"])

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    src_loc_arn, dst_loc_arn = outputs["SrcLocArn"], outputs["DstLocArn"]
    task_arn = outputs["TaskArn"]
    role_arn = outputs["RoleArn"]

    _assert_location(ctx, ds, "SrcLoc", src_loc_arn, outputs["SrcBucketName"],
                     outputs["SrcLocUri"], role_arn)
    _assert_location(ctx, ds, "DstLoc", dst_loc_arn, outputs["DstBucketName"],
                     outputs["DstLocUri"], role_arn)

    head = _ARN_HEAD.format(region=re.escape(ctx.region), account=ctx.account)
    assert re.fullmatch(head + r"task/task-[0-9a-f]{17}", task_arn), (
        f"Ref Task {task_arn!r} is not a DataSync task ARN in this account and region"
    )
    listed_tasks = _task_arns_named(ds, task_name)
    assert listed_tasks == [task_arn], (
        f"expected ListTasks to hold exactly Ref Task under its name, got {listed_tasks!r}"
    )
    task = ds.describe_task(TaskArn=task_arn)
    got = (task["Name"], task["SourceLocationArn"], task["DestinationLocationArn"], task["Status"])
    want = (task_name, src_loc_arn, dst_loc_arn, "AVAILABLE")
    assert got == want, f"DescribeTask (Name, Source, Destination, Status) is {got!r}, expected {want!r}"
    assert outputs["TaskStatus"] == task["Status"], (
        f"Fn::GetAtt Task.Status is {outputs['TaskStatus']!r}, DescribeTask reports {task['Status']!r}"
    )

    # The task is a child of both locations: remove it alone first, so its own delete is proven.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(task_name, with_task=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"task-removing update ended {status!r}"
    task_id = task_arn.rsplit("/", 1)[-1]
    task_gone = ("InvalidRequestException", f"Task {task_id} is not found.")
    expect_error(lambda: ds.describe_task(TaskArn=task_arn), *task_gone)
    still = ds.describe_location_s3(LocationArn=src_loc_arn)["LocationUri"]
    assert still == f"s3://{outputs['SrcBucketName']}/", (
        f"after removing only Task, SrcLoc reads back LocationUri {still!r}, expected it kept"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    for loc_arn in (src_loc_arn, dst_loc_arn):
        location_gone = ("InvalidRequestException", f"Location {loc_arn} is not found.")
        expect_error(lambda arn=loc_arn: ds.describe_location_s3(LocationArn=arn), *location_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
