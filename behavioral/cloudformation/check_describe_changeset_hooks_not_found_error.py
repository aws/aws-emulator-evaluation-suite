"""describe-changeset-hooks-not-found-error."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-changeset-hooks-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE_V1 = json.dumps(
    {"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "v1"}}}}
)
_TEMPLATE_V2 = json.dumps(
    {"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "v2"}}}}
)


_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChangeSetHooks for an unknown change set on a real stack is refused with ChangeSetNotFound."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-hooksmiss-")
    real_cs_name = ctx.unique_name("sim2real-cs-real-")
    bogus_cs_name = ctx.unique_name("sim2real-cs-bogus-")
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE_V1, Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    stack_status = _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)
    assert stack_status == "CREATE_COMPLETE", (
        f"prerequisite stack {stack_name!r} did not reach CREATE_COMPLETE, ended at {stack_status}"
    )

    # A real change set exists on this stack, but under a different name than the one we query.
    real_cs_id = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=real_cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE_V2,
        Tags=_TAGS,
    )["Id"]
    cs_status = _wait_change_set_status(
        cfn, real_cs_name, stack_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=120
    )
    assert cs_status == "CREATE_COMPLETE", (
        f"real change set {real_cs_name!r} ended at {cs_status}, expected CREATE_COMPLETE"
    )

    # Positive control: DescribeChangeSetHooks succeeds for the change set that really exists,
    # under its own name, on the same stack. Without this, a target that rejects every
    # DescribeChangeSetHooks call -- real change set or not -- would pass the negative
    # assertion below too, indistinguishable from one that only rejects the missing name.
    positive = cfn.describe_change_set_hooks(ChangeSetName=real_cs_name, StackName=stack_name)
    named = (positive.get("ChangeSetId"), positive.get("ChangeSetName"))
    assert named == (real_cs_id, real_cs_name), (
        f"DescribeChangeSetHooks for the real change set names {named!r}, expected "
        f"{(real_cs_id, real_cs_name)!r}"
    )

    got = _expect_error(
        lambda: cfn.describe_change_set_hooks(ChangeSetName=bogus_cs_name, StackName=stack_name)
    )
    # Real AWS returns the wire error code "ChangeSetNotFound" (no "Exception" suffix) -- distinct
    # from the modeled botocore exception class name ChangeSetNotFoundException.
    expected = ("ChangeSetNotFound", f"ChangeSet [{bogus_cs_name}] does not exist")
    assert got == expected, f"expected {expected!r}, got {got!r}"


# ===== helpers =====


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_stack_status(cfn, stack_name, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in target_statuses or not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name!r} did not reach {target_statuses} within {timeout_s}s, "
        f"stuck at {status}"
    )


def _wait_change_set_status(cfn, cs_name, stack_name, target_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)["Status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"change set {cs_name!r} did not reach {target_statuses} within {timeout_s}s, "
        f"stuck at {status}"
    )


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
