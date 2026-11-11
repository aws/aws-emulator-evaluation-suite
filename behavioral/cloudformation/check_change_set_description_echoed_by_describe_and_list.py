"""change-set-description-echoed-by-describe-and-list."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "change-set-description-echoed-by-describe-and-list"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TEMPLATE = json.dumps({"Description": "template description",
                        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}})


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A change set's Description is returned by DescribeChangeSet and ListChangeSets, distinct from
    the template's own Description, and a change set created without one carries none.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ChangeSetSummary.html
    """
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-csdesc-")
    described = ctx.unique_name("sim2real-behav-csdesc-a-")
    bare = ctx.unique_name("sim2real-behav-csdesc-b-")
    text = f"review {described} before executing"

    first = cf.create_change_set(StackName=stack_name, ChangeSetName=described,
                                 ChangeSetType="CREATE", TemplateBody=_TEMPLATE, Tags=_TAGS,
                                 Description=text)
    stack_id = first["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, first["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert cs.get("Description") == text, f"DescribeChangeSet Description: {cs.get('Description')!r}"

    second = cf.create_change_set(StackName=stack_id, ChangeSetName=bare, ChangeSetType="CREATE",
                                  TemplateBody=_TEMPLATE)
    other = _wait_change_set(cf, second["Id"], timeout_s=_cap(ctx, 180.0))
    assert other["Status"] == "CREATE_COMPLETE", f"second change set: {other.get('StatusReason')!r}"
    assert "Description" not in other, f"no Description was given: {other.get('Description')!r}"

    summaries = {s["ChangeSetName"]: s for s in cf.list_change_sets(StackName=stack_id)["Summaries"]}
    assert sorted(summaries) == sorted([described, bare]), sorted(summaries)
    assert summaries[described].get("Description") == text, summaries[described]
    assert "Description" not in summaries[bare], summaries[bare]

    # The stack's Description comes from the template, never from the change set.
    cf.execute_change_set(ChangeSetName=first["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"execute: {stack['StackStatus']!r}"
    assert stack.get("Description") == "template description", stack.get("Description")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
