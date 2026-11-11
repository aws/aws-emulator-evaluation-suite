"""change-set-revert-drift-restores-an-out-of-band-parameter-change."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-revert-drift-restores-an-out-of-band-parameter-change"
GROUP = "change_sets"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NO_CHANGES = ("The submitted information didn't contain changes. "
               "Submit different information to create a change set.")


def _template(name):
    return json.dumps({"Resources": {"P": {
        "Type": "AWS::SSM::Parameter",
        "Properties": {"Name": name, "Type": "String", "Value": "template"}}}})


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
    """After an out-of-band SSM write, a standard change set of the same template sees no changes; a
    DeploymentMode=REVERT_DRIFT one shows Modify from the actual value and executing it restores it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/drift-aware-change-sets.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csdrift-")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csdrift-"), Tags=_TAGS,
                               TemplateBody=_template(name))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"

    ssm.put_parameter(Name=name, Type="String", Value="drifted", Overwrite=True)

    # Control: a standard change set compares templates only, so it finds nothing to do.
    std = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE", UsePreviousTemplate=True,
                               ChangeSetName=ctx.unique_name("sim2real-xsvc-csdrift-std-"))["Id"]
    control = _wait_change_set(cf, std, timeout_s=_cap(ctx, 180.0))
    assert (control["Status"], control.get("StatusReason")) == ("FAILED", _NO_CHANGES), (
        f"standard change set: {(control['Status'], control.get('StatusReason'))!r}")

    drift = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 UsePreviousTemplate=True, DeploymentMode="REVERT_DRIFT",
                                 ChangeSetName=ctx.unique_name("sim2real-xsvc-csdrift-rev-"))["Id"]
    cs = _wait_change_set(cf, drift, IncludePropertyValues=True, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"drift-aware change set: {cs.get('StatusReason')!r}"
    assert cs.get("DeploymentMode") == "REVERT_DRIFT", cs.get("DeploymentMode")
    rc = _by_logical_id(cs)["P"]
    assert (rc["Action"], rc.get("Replacement"), rc.get("ResourceDriftStatus")) == (
        "Modify", "False", "MODIFIED"), rc
    targets = [(d["Target"].get("Name"), d["Target"].get("BeforeValue"),
                d["Target"].get("BeforeValueFrom"), d["Target"].get("AfterValue"),
                d["Target"].get("AfterValueFrom")) for d in rc["Details"]]
    assert targets == [("Value", "drifted", "ACTUAL_STATE", "template", "TEMPLATE")], targets

    cf.execute_change_set(ChangeSetName=drift)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"execute: {stack['StackStatus']!r}"
    value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert value == "template", f"REVERT_DRIFT must restore the template value, SSM reads {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
