"""change-set-import-without-deletion-policy-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-import-without-deletion-policy-rejected"
GROUP = "change-set-import"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name, *, deletion_policy="Retain"):
    resource = {"Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": "String", "Value": "existing"}}
    if deletion_policy:
        resource["DeletionPolicy"] = deletion_policy
    return json.dumps({"Resources": {"P": resource}})


def _to_import(name):
    return [{"ResourceType": "AWS::SSM::Parameter", "LogicalResourceId": "P",
             "ResourceIdentifier": {"Name": name}}]


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

@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IMPORT change set whose template gives the imported resource no DeletionPolicy is refused
    with the exact ValidationError and creates no stack; with DeletionPolicy Retain it is an Import.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csimpdp-")
    ssm.put_parameter(Name=name, Type="String", Value="existing", Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    stack_name = ctx.unique_name("sim2real-xsvc-csimpdp-")
    cs_name = ctx.unique_name("sim2real-xsvc-csimpdp-cs-")

    got = _error(lambda: cf.create_change_set(
        StackName=stack_name, ChangeSetName=cs_name, ChangeSetType="IMPORT",
        TemplateBody=_template(name, deletion_policy=None), ResourcesToImport=_to_import(name)))
    assert got == (
        "ValidationError",
        "The following resources to import [P] must have DeletionPolicy attribute specified in the "
        "template.",
    ), f"IMPORT without DeletionPolicy answered {got!r}"
    absent = _error(lambda: cf.describe_stacks(StackName=stack_name))
    assert absent == ("ValidationError", f"Stack with id {stack_name} does not exist"), absent

    # Control: the same import with DeletionPolicy Retain is classified Import of the parameter.
    created = cf.create_change_set(
        StackName=stack_name, ChangeSetName=cs_name, ChangeSetType="IMPORT",
        TemplateBody=_template(name), ResourcesToImport=_to_import(name))
    ctx.on_cleanup(lambda: _delete_stack(cf, created["StackId"]))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"control change set: {cs.get('StatusReason')!r}"
    rc = _by_logical_id(cs)["P"]
    assert (rc["Action"], rc.get("PhysicalResourceId")) == ("Import", name), rc
    value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert value == "existing", f"the parameter to import must keep its value: expected 'existing', got {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
