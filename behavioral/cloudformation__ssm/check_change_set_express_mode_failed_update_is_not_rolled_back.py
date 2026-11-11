"""change-set-express-mode-failed-update-is-not-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-express-mode-failed-update-is-not-rolled-back"
GROUP = "change_sets"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name, c_name, value, *, collide):
    resources = {"A": {"Type": "AWS::SSM::Parameter",
                       "Properties": {"Name": name, "Type": "String", "Value": value}}}
    if collide:
        # C and D are both new to this change set, so neither name exists before it is created
        # and CloudFormation's early validation cannot see the collision; D takes C's Name
        # through Ref C, so it fails only once execution actually creates C.
        resources["C"] = {"Type": "AWS::SSM::Parameter",
                          "Properties": {"Name": c_name, "Type": "String", "Value": "c"}}
        resources["D"] = {"Type": "AWS::SSM::Parameter",
                          "Properties": {"Name": {"Ref": "C"}, "Type": "String", "Value": "d"}}
    return json.dumps({"Resources": resources})


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll_value(ssm, name, want, *, timeout_s):
    """Read the parameter until it holds ``want``; EXPRESS completes before resources settle.

    Returns the last value read (None while the parameter does not exist yet).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
            value = None
        if value == want or time.monotonic() > deadline:
            return value
        time.sleep(2)


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _delete_param(ssm, name):
    """Delete an SSM parameter; only ParameterNotFound means it is already gone."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An UPDATE change set with DeploymentConfig Mode EXPRESS that fails stops at UPDATE_FAILED with
    the exact reason and no rollback: the update already applied to A stays in SSM.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeploymentConfig.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csexpu-")
    c_name = "/" + ctx.unique_name("sim2real-xsvc-csexpu-c-")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    ctx.on_cleanup(lambda: _delete_param(ssm, c_name))
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csexpu-"), Tags=_TAGS,
                               TemplateBody=_template(name, c_name, "v1",
                                                       collide=False))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"

    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 ChangeSetName=ctx.unique_name("sim2real-xsvc-csexpu-cs-"),
                                 TemplateBody=_template(name, c_name, "v2", collide=True),
                                 DeploymentConfig={"Mode": "EXPRESS"})["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert cs.get("DeploymentConfig") == {"Mode": "EXPRESS", "DisableRollback": True}, (
        f"DescribeChangeSet DeploymentConfig: {cs.get('DeploymentConfig')!r}")

    cf.execute_change_set(ChangeSetName=cs_id)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_FAILED", (
        f"EXPRESS update must stop at UPDATE_FAILED, got {stack['StackStatus']!r}")
    assert stack.get("StackStatusReason") == (
        "The following resource(s) failed to create via Express Mode: [D]. "
    ), stack.get("StackStatusReason")
    statuses = {e["ResourceStatus"] for e in _events(cf, stack_id)}
    assert not {s for s in statuses if s.startswith("UPDATE_ROLLBACK")}, sorted(statuses)
    value = _poll_value(ssm, name, "v2", timeout_s=_cap(ctx, 120.0))
    assert value == "v2", f"A's applied update must not be reverted, SSM reads {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
