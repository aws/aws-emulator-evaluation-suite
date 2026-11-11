"""deploy-iottwinmaker-sync-job-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iottwinmaker-sync-job-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iottwinmaker"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_SYNC_SOURCE = "SITEWISE"
# A SITEWISE sync job takes minutes to create and to delete: its waits get this long.
_SYNC_WAIT_S = 900.0
_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "iottwinmaker.amazonaws.com"},
         "Action": "sts:AssumeRole"}
    ],
}


def _workspace_resources(bucket, role_name, ws_id):
    """The workspace's bucket, role and Workspace; the twinmaker types take Tags as a map."""
    return {
        "Bucket": {"Type": "AWS::S3::Bucket",
                   "Properties": {"BucketName": bucket,
                                  "Tags": [{"Key": "sim2real-tm", "Value": ws_id}]}},
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_POLICY,
                "Policies": [{
                    "PolicyName": "s3access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket",
                                       "s3:PutObject", "s3:DeleteObject"],
                            "Resource": [
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"},
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"},
                            ],
                        }],
                    },
                }],
                "Tags": [{"Key": "sim2real-tm", "Value": ws_id}],
            },
        },
        "Workspace": {
            "Type": "AWS::IoTTwinMaker::Workspace",
            "DependsOn": ["Role", "Bucket"],
            "Properties": {
                "WorkspaceId": ws_id,
                "Description": "sim2real twinmaker workspace",
                "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                "S3Location": {"Fn::GetAtt": ["Bucket", "Arn"]},
                "Tags": {"sim2real-tm": ws_id},
            },
        },
    }


def _pages(fn, key, **kw):
    """Every item under ``key`` across all nextToken pages of ``fn``."""
    items, token = [], None
    while True:
        page = fn(**kw, **({"nextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return items


def _own_tags(tm, arn):
    """The resource's own ``sim2real-`` tags (stack-tag propagation is not part of the claim)."""
    tags_map = tm.list_tags_for_resource(resourceARN=arn)["tags"]
    return {k: v for k, v in tags_map.items() if k.startswith("sim2real-")}


def _template(bucket, role_name, sync_role_name, ws_id, with_job=True):
    resources = _workspace_resources(bucket, role_name, ws_id)
    resources["SyncRole"] = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "RoleName": sync_role_name,
            "AssumeRolePolicyDocument": _TRUST_POLICY,
            "Policies": [{
                "PolicyName": "sitewise-read",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["iotsitewise:Describe*", "iotsitewise:List*",
                                   "iotsitewise:Get*"],
                        "Resource": "*",
                    }],
                },
            }],
            "Tags": [{"Key": "sim2real-tm", "Value": ws_id}],
        },
    }
    outputs = {
        "SyncRoleArn": {"Value": {"Fn::GetAtt": ["SyncRole", "Arn"]}},
        "WorkspaceRef": {"Value": {"Ref": "Workspace"}},
    }
    if with_job:
        resources["SyncJob"] = {
            "Type": "AWS::IoTTwinMaker::SyncJob",
            "DependsOn": ["Workspace", "SyncRole"],
            "Properties": {
                "WorkspaceId": {"Ref": "Workspace"},
                "SyncSource": _SYNC_SOURCE,
                "SyncRole": {"Fn::GetAtt": ["SyncRole", "Arn"]},
                "Tags": {"sim2real-tm": ws_id},
            },
        }
        outputs.update({
            "SyncJobRef": {"Value": {"Ref": "SyncJob"}},
            "SyncJobArn": {"Value": {"Fn::GetAtt": ["SyncJob", "Arn"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation IoTTwinMaker SITEWISE SyncJob reaches ACTIVE with its declared SyncRole.

    Ref is WorkspaceId|SyncSource of the job IoTTwinMaker lists in the workspace; the role and
    tags read back, and an update dropping the job removes it while the workspace answers.
    """
    cfn = ctx.client("cloudformation")
    tm = ctx.client("iottwinmaker")
    bucket = ctx.unique_name("sim2real-tmsync-")
    role_name = ctx.unique_name("sim2real-tmsync-role-")
    sync_role_name = ctx.unique_name("sim2real-tmsync-syncrole-")
    ws_id = ctx.unique_name("sim2real-tmsync-ws-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-tmsync-"),
                            _template(bucket, role_name, sync_role_name, ws_id),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=_SYNC_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    listed = [(s["arn"], s["status"]["state"])
              for s in _pages(tm.list_sync_jobs, "syncJobSummaries", workspaceId=ws_id)
              if s["syncSource"] == _SYNC_SOURCE]
    assert listed == [(out["SyncJobArn"], "ACTIVE")], f"ListSyncJobs {listed!r}"
    assert out["SyncJobRef"] == f"{ws_id}|{_SYNC_SOURCE}", f"Ref {out['SyncJobRef']!r}"
    job = tm.get_sync_job(workspaceId=ws_id, syncSource=_SYNC_SOURCE)
    got = (job["arn"], job["syncRole"], job["status"]["state"], _own_tags(tm, job["arn"]))
    assert got == (out["SyncJobArn"], out["SyncRoleArn"], "ACTIVE", {"sim2real-tm": ws_id}), (
        f"sync job {got!r}"
    )

    # Child before parent: the update drops only the job while its workspace answers.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_NAMED_IAM"],
                     TemplateBody=_template(bucket, role_name, sync_role_name, ws_id, False))
    status = wait_stack(cfn, stack_id, timeout_s=_SYNC_WAIT_S)
    assert status == "UPDATE_COMPLETE", f"job-removing update ended {status!r}"
    assert tm.get_workspace(workspaceId=ws_id)["workspaceId"] == ws_id, "workspace gone"
    gone = ("ResourceNotFoundException", "Provided Sync Job does not exist!")
    expect_error(lambda: tm.get_sync_job(workspaceId=ws_id, syncSource=_SYNC_SOURCE), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
