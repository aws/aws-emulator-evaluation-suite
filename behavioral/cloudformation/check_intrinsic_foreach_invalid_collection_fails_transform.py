"""intrinsic-foreach-invalid-collection-fails-transform."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "intrinsic-foreach-invalid-collection-fails-transform"
GROUP = "language-extensions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _template(collection) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::LanguageExtensions",
        "Resources": {
            "Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Fn::ForEach::Handles": ["Name", collection, {
                "Handle${Name}": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            }],
        },
    })


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


def _create(ctx, cf, body: str) -> str:
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-foreach-bad-"), TemplateBody=body,
                               Capabilities=["CAPABILITY_AUTO_EXPAND"], Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    return stack_id


def _stack_events(cf, stack_id: str) -> list:
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


# axis:happy-path — CreateStack is accepted; the transform failure is an asynchronous rollback
# with an exact reason, not a refused call.
@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A Fn::ForEach whose collection is a string, not a list, fails the LanguageExtensions transform:
    the stack rolls back with the exact transform reason and provisions nothing; a list deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-foreach.html
    """
    cf = ctx.client("cloudformation")

    control = _create(ctx, cf, _template(["Alpha"]))
    bad = _create(ctx, cf, _template("Alpha"))

    good = _settle(cf, control)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"control with a list collection: {good['StackStatus']!r}: {good.get('StackStatusReason')!r}"
    )
    logical = sorted(r["LogicalResourceId"] for r in cf.describe_stack_resources(StackName=control)["StackResources"])
    assert logical == ["Anchor", "HandleAlpha"], f"control resources: {logical!r}"

    failed = _settle(cf, bad)
    assert failed["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a string collection must roll back; got {failed['StackStatus']!r}: {failed.get('StackStatusReason')!r}"
    )
    resources = cf.describe_stack_resources(StackName=bad)["StackResources"]
    assert resources == [], f"a failed transform must provision nothing; got {resources!r}"
    rollback = [
        e.get("ResourceStatusReason") for e in _stack_events(cf, bad)
        if e["LogicalResourceId"] == failed["StackName"] and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
    ]
    expected = (
        "Transform AWS::LanguageExtensions failed with: Fn::ForEach layout is incorrect. "
        "Rollback requested by user."
    )
    assert rollback == [expected], f"the rollback reason differs: {rollback!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
