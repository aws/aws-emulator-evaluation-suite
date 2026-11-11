"""change-set-import-existing-resources-without-a-match-adds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-import-existing-resources-without-a-match-adds"
GROUP = "change-set-import"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name, *, deletion_policy="Retain"):
    resource = {"Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": "String", "Value": "existing"}}
    if deletion_policy:
        resource["DeletionPolicy"] = deletion_policy
    return json.dumps({"Resources": {"P": resource}})


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


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


def _delete_param(ssm, name):
    """Delete an SSM parameter; only ParameterNotFound means it is already gone."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _by_logical_id(cs):
    """The change set's ResourceChange entries keyed by LogicalResourceId."""
    return {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}

@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """With ImportExistingResources and no existing parameter of the template's name, the change set
    is a plain Add that echoes the flag, and executing it creates the parameter in SSM.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-automatically.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csier-")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    precheck = _error(lambda: ssm.get_parameter(Name=name))
    assert precheck == ("ParameterNotFound", ""), f"parameter {name!r} must not pre-exist: {precheck!r}"

    created = cf.create_change_set(
        StackName=ctx.unique_name("sim2real-xsvc-csier-"), ChangeSetType="CREATE", Tags=_TAGS,
        ChangeSetName=ctx.unique_name("sim2real-xsvc-csier-cs-"),
        TemplateBody=_template(name, deletion_policy="Delete"), ImportExistingResources=True)
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert cs.get("ImportExistingResources") is True, cs.get("ImportExistingResources")
    rc = _by_logical_id(cs)["P"]
    assert (rc["Action"], rc.get("PhysicalResourceId")) == ("Add", None), rc

    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"execute: {stack['StackStatus']!r}"
    value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert value == "existing", f"parameter {name!r} after CREATE_COMPLETE: {value!r}"
    phys = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="P")
    assert phys["StackResourceDetail"]["PhysicalResourceId"] == name, phys


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
