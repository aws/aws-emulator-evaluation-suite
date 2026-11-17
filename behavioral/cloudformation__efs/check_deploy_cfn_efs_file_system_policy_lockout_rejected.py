"""deploy-cfn-efs-file-system-policy-lockout-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-efs-file-system-policy-lockout-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "efs"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_LOCKOUT_REJECTED = (
    "This policy would prevent future FileSystemPolicy updates. Retry the request with the "
    "BypassPolicyLockoutSafetyCheck parameter to apply this policy. (Service: Efs, Status Code: "
    "400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(name: str, action: str) -> str:
    """An encrypted file system tagged Name=``name`` whose policy denies everyone ``action``."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Fs": {
                    "Type": "AWS::EFS::FileSystem",
                    "Properties": {
                        "Encrypted": True,
                        "FileSystemTags": [{"Key": "Name", "Value": name}],
                        "FileSystemPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": action}
                            ],
                        },
                    },
                }
            },
            "Outputs": {"FileSystemIdRef": {"Value": {"Ref": "Fs"}}},
        }
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, cfn, stack_id, terminal=_TERMINAL, timeout_s=600.0):
    """Poll DescribeStacks by StackId every 3 s until a status in ``terminal``; return it."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _events(cfn, stack_id):
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


def _delete_stack(ctx, cfn, stack_id):
    """Delete by StackId whatever its state; raise unless it reaches DELETE_COMPLETE."""
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _wait_stack(ctx, cfn, stack_id, _TERMINAL, _DELETE_BUDGET_S)
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    if status != "DELETE_COMPLETE":
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in _events(cfn, stack_id)
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def _handler_reason(reason):
    """``(message, HandlerErrorCode)`` of a resource-handler reason, with only the request id,
    request token and SDK attempt count masked."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", m["message"])
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


def _named(efs, name):
    """FileSystemIds of every file system whose Name tag is ``name``, across every page."""
    pages = efs.get_paginator("describe_file_systems").paginate()
    return [fs["FileSystemId"] for p in pages for fs in p["FileSystems"] if fs.get("Name") == name]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A FileSystemPolicy denying everyone PutFileSystemPolicy fails CREATE with the exact lockout
    reason and rolls back, leaving no file system with its Name tag; the same statement denying
    ClientMount deploys and DescribeFileSystemPolicy reads it back exactly."""
    cfn = ctx.client("cloudformation")
    efs = ctx.client("efs")

    lockout_name = ctx.unique_name("sim2real-behav-efs-lockout-")
    lockout_stack = ctx.unique_name("sim2real-behav-stack-")
    template = _template(lockout_name, "elasticfilesystem:PutFileSystemPolicy")
    lockout_id = cfn.create_stack(StackName=lockout_stack, TemplateBody=template)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, lockout_id))

    status = _wait_stack(ctx, cfn, lockout_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    fs_failures = [
        e.get("ResourceStatusReason")
        for e in _events(cfn, lockout_id)
        if e["LogicalResourceId"] == "Fs" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(fs_failures) == 1, (
        f"expected exactly one Fs CREATE_FAILED event, got {fs_failures!r}"
    )
    got = _handler_reason(fs_failures[0])
    assert got == _LOCKOUT_REJECTED, (
        f"Fs CREATE_FAILED reason {got!r}, expected {_LOCKOUT_REJECTED!r}"
    )
    left = _named(efs, lockout_name)
    assert left == [], f"the rolled-back stack left file systems named {lockout_name!r}: {left!r}"

    # Positive control: the same statement shape, scoped to a non-lockout action, deploys.
    control_name = ctx.unique_name("sim2real-behav-efs-control-")
    control_stack = ctx.unique_name("sim2real-behav-stack-")
    template = _template(control_name, "elasticfilesystem:ClientMount")
    control_id = cfn.create_stack(StackName=control_stack, TemplateBody=template)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, control_id))
    status = _wait_stack(ctx, cfn, control_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=control_id)["Stacks"][0]["Outputs"]
    }
    control_fs_id = outputs["FileSystemIdRef"]
    assert _named(efs, control_name) == [control_fs_id], (
        f"expected exactly the control file system {control_fs_id!r} named {control_name!r}"
    )
    fs_arn = efs.describe_file_systems(FileSystemId=control_fs_id)["FileSystems"][0][
        "FileSystemArn"
    ]
    described = json.loads(efs.describe_file_system_policy(FileSystemId=control_fs_id)["Policy"])
    want = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "elasticfilesystem:ClientMount",
                "Resource": fs_arn,
            }
        ],
    }
    assert described == want, f"control file system policy {described!r}, expected {want!r}"

    _delete_stack(ctx, cfn, control_id)
    got = _error(lambda: efs.describe_file_system_policy(FileSystemId=control_fs_id))
    want_gone = ("FileSystemNotFound", f"File system '{control_fs_id}' does not exist.")
    assert got == want_gone, f"policy read after the stack delete: {got!r}, expected {want_gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
