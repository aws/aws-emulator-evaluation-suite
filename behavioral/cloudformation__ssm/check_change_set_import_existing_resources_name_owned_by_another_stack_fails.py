"""change-set-import-existing-resources-name-owned-by-another-stack-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-import-existing-resources-name-owned-by-another-stack-fails"
GROUP = "change-set-import"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name, *, deletion_policy="Retain"):
    resource = {"Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": "String", "Value": "existing"}}
    if deletion_policy:
        resource["DeletionPolicy"] = deletion_policy
    return json.dumps({"Resources": {"P": resource}})


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
    """ImportExistingResources does not adopt a parameter another stack manages: the change set ends
    FAILED with the exact StatusReason and the owner keeps it; an unmanaged one is adopted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-automatically.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    owned = "/" + ctx.unique_name("sim2real-xsvc-csierown-")
    free = "/" + ctx.unique_name("sim2real-xsvc-csierown-free-")
    ctx.on_cleanup(lambda: _delete_param(ssm, owned))
    owner = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csierown-a-"), Tags=_TAGS,
                            TemplateBody=_template(owned, deletion_policy="Delete"))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, owner))
    stack = _wait_stack(cf, owner, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"owner stack: {stack['StackStatus']!r}"

    created = cf.create_change_set(
        StackName=ctx.unique_name("sim2real-xsvc-csierown-b-"), ChangeSetType="CREATE", Tags=_TAGS,
        ChangeSetName=ctx.unique_name("sim2real-xsvc-csierown-cs-"),
        TemplateBody=_template(owned), ImportExistingResources=True)
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert (cs["Status"], cs.get("StatusReason")) == (
        "FAILED",
        f"{owned} already exists in stack {owner}",
    ), f"auto-import of a managed name: {(cs['Status'], cs.get('StatusReason'))!r}"
    pending = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert (cs["ExecutionStatus"], pending) == ("UNAVAILABLE", "REVIEW_IN_PROGRESS"), (
        f"the FAILED change set must be unexecutable and the new stack still in review: "
        f"ExecutionStatus {cs['ExecutionStatus']!r}, stack {pending!r}")
    owner_res = cf.describe_stack_resource(StackName=owner, LogicalResourceId="P")
    assert owner_res["StackResourceDetail"]["PhysicalResourceId"] == owned, owner_res
    owned_value = ssm.get_parameter(Name=owned)["Parameter"]["Value"]
    assert owned_value == "existing", f"owner's parameter value: expected 'existing', got {owned_value!r}"

    # Control: an unmanaged parameter of the template's name is adopted as an Import.
    ssm.put_parameter(Name=free, Type="String", Value="existing", Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_param(ssm, free))
    ok_id = cf.create_change_set(
        StackName=stack_id, ChangeSetType="CREATE",
        ChangeSetName=ctx.unique_name("sim2real-xsvc-csierown-ok-"),
        TemplateBody=_template(free), ImportExistingResources=True)["Id"]
    ok = _wait_change_set(cf, ok_id, timeout_s=_cap(ctx, 180.0))
    assert ok["Status"] == "CREATE_COMPLETE", f"control change set: {ok.get('StatusReason')!r}"
    rc = _by_logical_id(ok)["P"]
    assert (rc["Action"], rc.get("PhysicalResourceId")) == ("Import", free), rc

    cf.execute_change_set(ChangeSetName=ok_id)
    executed = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert executed["StackStatus"] == "CREATE_COMPLETE", f"execute control: {executed['StackStatus']!r}"
    phys = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="P")
    assert phys["StackResourceDetail"]["PhysicalResourceId"] == free, phys
    free_value = ssm.get_parameter(Name=free)["Parameter"]["Value"]
    assert free_value == "existing", f"imported parameter value: expected 'existing', got {free_value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
