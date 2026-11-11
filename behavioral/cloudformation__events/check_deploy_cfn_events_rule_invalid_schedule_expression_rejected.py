"""deploy-cfn-events-rule-invalid-schedule-expression-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-events-rule-invalid-schedule-expression-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

_GOOD_SCHEDULE = "rate(5 minutes)"
_BAD_SCHEDULE = "rate(5 whatevers)"

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(name: str, schedule: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {"Name": name, "ScheduleExpression": schedule, "State": "ENABLED"},
                },
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Events::Rule with a malformed ScheduleExpression fails with EventBridge's
    invalid-schedule error and is never created, while the same template with a valid schedule deploys."""
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    good_name = ctx.unique_name("sim2real-behav-cfnok-")
    bad_name = ctx.unique_name("sim2real-behav-cfnbad-")
    good_stack = ctx.unique_name("sim2real-behav-stack-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-stack-bad-")

    # Positive control: the identical template with a valid schedule, through CloudFormation.
    _create(ctx, cfn, good_stack, _template(good_name, _GOOD_SCHEDULE))
    status = _poll_until_terminal(cfn, good_stack, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_rule = events.describe_rule(Name=good_name)
    assert good_rule["ScheduleExpression"] == _GOOD_SCHEDULE, (
        f"positive control: expected ScheduleExpression {_GOOD_SCHEDULE!r}, "
        f"got {good_rule['ScheduleExpression']!r}"
    )

    # The one thing broken: the schedule names a unit EventBridge does not accept.
    _create(ctx, cfn, bad_stack, _template(bad_name, _BAD_SCHEDULE))
    status = _poll_until_terminal(cfn, bad_stack, timeout_s=180.0)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"
    reason = _failed_reason(cfn, bad_stack, "Rule")
    match = _REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = ("Parameter ScheduleExpression is not valid.", "EventBridge", "400", "GeneralServiceException")
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    code, message = _error(lambda: events.describe_rule(Name=bad_name))
    assert (code, message) == ("ResourceNotFoundException", f"Rule {bad_name} does not exist on EventBus default."), (
        f"expected the malformed rule {bad_name!r} to never exist, got {code!r}: {message!r}"
    )

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cfn, stack_name)
        got = _error(lambda stack_name=stack_name: cfn.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the delete of {stack_name}: {got!r}"
        )
    got = _error(lambda: events.describe_rule(Name=good_name))
    assert got == ("ResourceNotFoundException", f"Rule {good_name} does not exist on EventBus default."), (
        f"the control rule after its stack delete: {got!r}"
    )


def _create(ctx, cfn, stack_name: str, body: str) -> None:
    """CreateStack with its delete registered at once."""
    cfn.create_stack(
        StackName=stack_name, TemplateBody=body, DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event."""
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
