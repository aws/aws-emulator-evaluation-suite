"""deploy-eventbus-named-default-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventbus-named-default-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an AWS::Events::EventBus named 'default' is rejected before provisioning
    any resource, because every account already owns a bus of that name; that pre-existing default
    bus is untouched and still describable throughout.
    """
    cfn = ctx.client("cloudformation")
    ev = ctx.client("events")
    stack_name = ctx.unique_name("sim2real-behav-bus-default-stack-")

    default_before = ev.describe_event_bus(Name="default")
    assert default_before["Name"] == "default", (
        f"expected the account's default event bus, got {default_before!r}"
    )

    template = json.dumps({
        "Resources": {"Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": "default"}}}
    })
    cfn.create_stack(StackName=stack_name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == stack_name and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    expected_reason = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
        "issues with resource and property details, resolve each error, then retry the operation."
    )
    assert stack_failed_reasons and stack_failed_reasons[0] == expected_reason, (
        f"expected the stack's CREATE_FAILED reason to be {expected_reason!r}, "
        f"got {stack_failed_reasons!r}"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "Bus", "AWS::Events::EventBus", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
        "Resource of type 'AWS::Events::EventBus' with identifier 'default' already exists.",
        "/Resources/Bus",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )

    default_after = ev.describe_event_bus(Name="default")
    assert default_after["Arn"] == default_before["Arn"], (
        "the account's pre-existing default event bus must be untouched by the rollback"
    )

    _delete_stack(cfn, stack_name)
    try:
        gone = cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"the rejected stack is still described after its delete: {gone!r}")
    assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks after the in-band delete: {got!r}"
    )
    assert ev.describe_event_bus(Name="default")["Arn"] == default_before["Arn"], (
        "the account's default event bus must survive the rejected stack's delete"
    )


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
