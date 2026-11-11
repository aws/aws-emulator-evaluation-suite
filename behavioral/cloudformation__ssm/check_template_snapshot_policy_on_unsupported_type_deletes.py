"""template-snapshot-policy-on-unsupported-type-deletes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-snapshot-policy-on-unsupported-type-deletes"
GROUP = "deletion-policy"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _template(replaced: str, deleted: str) -> str:
    def param(name: str) -> dict:
        return {"Type": "AWS::SSM::Parameter", "Properties": {"Name": name, "Type": "String", "Value": "sim2real"}}

    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Replaced": {**param(replaced), "UpdateReplacePolicy": "Snapshot"},
            "Deleted": {**param(deleted), "DeletionPolicy": "Snapshot"},
        },
    })


def _settle(cf, stack_id: str, start: str = "") -> dict:
    """Poll DescribeStacks by StackId until the status is neither *_IN_PROGRESS nor ``start``."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        if not status.endswith("_IN_PROGRESS") and status != start:
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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except the named not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Snapshot on a type with no snapshots falls back to Delete: a replacement removes the old SSM
    parameter under UpdateReplacePolicy Snapshot, and DeleteStack removes one under DeletionPolicy Snapshot.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-updatereplacepolicy.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    old, new, deleted = ("/" + ctx.unique_name(f"sim2real-behav-snap-{k}-") for k in ("old", "new", "del"))
    for name in (old, new, deleted):
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-snap-"), TemplateBody=_template(old, deleted),
                               Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )

    cf.update_stack(StackName=stack_id, TemplateBody=_template(new, deleted))
    updated = _settle(cf, stack_id, start="CREATE_COMPLETE")
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    physical = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Replaced")["StackResourceDetail"]
    assert physical["PhysicalResourceId"] == new, f"Replaced must now be {new}; got {physical['PhysicalResourceId']!r}"
    assert ssm.get_parameter(Name=new)["Parameter"]["Value"] == "sim2real", "the replacement parameter is missing"
    code = _error(lambda: ssm.get_parameter(Name=old))
    assert code == ("ParameterNotFound", ""), f"the replaced parameter must be deleted, not kept; got {code!r}"

    _delete_stack(cf, stack_id)
    for name in (new, deleted):
        code = _error(lambda n=name: ssm.get_parameter(Name=n))
        assert code == ("ParameterNotFound", ""), f"{name} must be deleted with the stack; got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
