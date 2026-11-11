"""change-set-express-mode-create-then-express-update-stack-and-delete-stack."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-express-mode-create-then-express-update-stack-and-delete-stack"
GROUP = "change_sets"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name, value):
    return json.dumps({"Resources": {"P": {
        "Type": "AWS::SSM::Parameter",
        "Properties": {"Name": name, "Type": "String", "Value": value}}}})


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


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


def _delete_param(ssm, name):
    """Delete an SSM parameter; only ParameterNotFound means it is already gone."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeploymentConfig Mode EXPRESS is accepted on CreateChangeSet, UpdateStack and DeleteStack: each
    operation completes, DescribeStacks reports EXPRESS, and SSM shows the create, update and delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeploymentConfig.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csexp-")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    express = {"Mode": "EXPRESS"}

    created = cf.create_change_set(StackName=ctx.unique_name("sim2real-xsvc-csexp-"),
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csexp-cs-"),
                                   ChangeSetType="CREATE", TemplateBody=_template(name, "v1"),
                                   DeploymentConfig=express, Tags=_TAGS)
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"express create: {stack['StackStatus']!r}"
    assert stack.get("DeploymentConfig") == {"Mode": "EXPRESS", "DisableRollback": True}, (
        stack.get("DeploymentConfig"))
    value = _poll_value(ssm, name, "v1", timeout_s=_cap(ctx, 120.0))
    assert value == "v1", f"the express create must reach SSM, read {value!r}"

    cf.update_stack(StackName=stack_id, TemplateBody=_template(name, "v2"),
                    DeploymentConfig=express)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"express update: {stack['StackStatus']!r}"
    assert stack.get("DeploymentConfig") == {"Mode": "EXPRESS", "DisableRollback": True}, (
        stack.get("DeploymentConfig"))
    value = _poll_value(ssm, name, "v2", timeout_s=_cap(ctx, 120.0))
    assert value == "v2", f"the express update must reach SSM, read {value!r}"

    cf.delete_stack(StackName=stack_id, DeploymentConfig=express)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "DELETE_COMPLETE", f"express delete: {stack['StackStatus']!r}"
    _poll_value(ssm, name, None, timeout_s=_cap(ctx, 120.0))
    assert _error(lambda: ssm.get_parameter(Name=name)) == ("ParameterNotFound", ""), (
        "the express delete must remove the parameter")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
