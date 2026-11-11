"""cfn-ssm-parameter-missing-required-properties-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-missing-required-properties-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(props: dict) -> str:
    return json.dumps({"Resources": {"P": {"Type": "AWS::SSM::Parameter", "Properties": props}}})


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(logical id, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
             e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::SSM::Parameter missing Value, or missing Type, fails pre-provisioning property
    validation with the exact missing-property reason and creates no parameter.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    # Positive control: both required properties present.
    good_name = "/" + ctx.unique_name("sim2real-behav-ssmreq-ok-")
    good_stack = ctx.unique_name("sim2real-behav-ssmreq-ok-stack-")
    cfn.create_stack(StackName=good_stack, TemplateBody=_template({
        "Name": good_name, "Type": "String", "Value": "control-value",
    }))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    got_value = ssm.get_parameter(Name=good_name)["Parameter"]["Value"]
    assert got_value == "control-value", f"control parameter reads back as {got_value!r}"

    cases = [
        ("missing Value", {"Type": "String"}, "Required property [Value] not found"),
        ("missing Type", {"Value": "x"}, "Required property [Type] not found"),
    ]
    for label, props, expected_reason in cases:
        bad_name = "/" + ctx.unique_name(f"sim2real-behav-ssmreq-bad-{label.split()[-1].lower()}-")
        bad_stack = ctx.unique_name(f"sim2real-behav-ssmreq-bad-{label.split()[-1].lower()}-stack-")
        full_props = dict(props)
        full_props["Name"] = bad_name
        cfn.create_stack(StackName=bad_stack, TemplateBody=_template(full_props))
        ctx.on_cleanup(lambda bad_stack=bad_stack: _delete_stack(cfn, bad_stack))
        status = _wait_terminal(cfn, bad_stack)
        assert status == "ROLLBACK_COMPLETE", (
            f"{label}: expected ROLLBACK_COMPLETE, got {status!r}"
        )
        found = _validation_errors(cfn, bad_stack)
        want = [("P", "PROPERTY_VALIDATION", "FAILED", "FAIL", expected_reason, "/Resources/P/Properties")]
        assert found == want, f"{label}: validation errors expected {want!r}, got {found!r}"
        resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
        assert resources == [], f"{label}: a stack rejected before provisioning must list no resources, got {resources!r}"
        got = _error(lambda bad_name=bad_name: ssm.get_parameter(Name=bad_name))
        assert got == ("ParameterNotFound", ""), f"{label}: GetParameter on the rejected name: {got!r}"

    # Control survives all the rejections above.
    still = ssm.get_parameter(Name=good_name)["Parameter"]["Value"]
    assert still == "control-value", f"control parameter changed to {still!r} after the rejections"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
