"""delete-resource-during-in-progress-create-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-during-in-progress-create-conflict"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol", "cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResource on an identifier whose create is IN_PROGRESS fails with
    ConcurrentOperationException, leaves the create running, and succeeds once it finishes."""
    cc = ctx.client("cloudcontrol")
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-ccrace-")

    token, identifier = _start_held_create(ctx, cc, cfn, stack_name)

    code, message = _error(lambda: cc.delete_resource(TypeName=STACK_TYPE, Identifier=identifier))
    assert code == "ConcurrentOperationException", f"expected ConcurrentOperationException, got {code}"
    expected_message = f"Concurrent operation found for resource {identifier} with RequestToken {token}"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the refused delete neither ended nor cancelled the held create.
    held = _status(cc, token)
    assert held["OperationStatus"] == "IN_PROGRESS", f"the refused delete disturbed the create: {held}"

    _release(ctx, cfn, stack_name)
    create_final = _poll_until(
        lambda: _status(cc, token), lambda e: e["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=180, description=f"create request {token} reaching a terminal state",
    )
    assert create_final["OperationStatus"] == "SUCCESS", f"create was disrupted: {create_final}"

    # Positive control: once the create has finished, the same delete is accepted and completes.
    delete_token = cc.delete_resource(TypeName=STACK_TYPE, Identifier=identifier)["ProgressEvent"][
        "RequestToken"
    ]
    delete_final = _poll_until(
        lambda: _status(cc, delete_token), lambda e: e["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=300, interval_s=3.0, description=f"delete request {delete_token} terminating",
    )
    assert delete_final["OperationStatus"] == "SUCCESS", f"control delete failed: {delete_final}"
    stack_status = cfn.describe_stacks(StackName=identifier)["Stacks"][0]["StackStatus"]
    assert stack_status == "DELETE_COMPLETE", f"the deleted stack reports {stack_status!r}"


def _error(fn):
    """The (code, message) of the ClientError fn() raises. Raises if the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call returned {result!r}")


STACK_TYPE = "AWS::CloudFormation::Stack"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
# A stack whose WaitCondition waits for a signal only this check sends: the Cloud Control create
# request stays IN_PROGRESS until the check releases it, so the in-progress window is held here
# and never depends on how fast the target provisions anything.
HELD_TEMPLATE = json.dumps({
    "Resources": {
        "Gate": {
            "Type": "AWS::CloudFormation::WaitCondition",
            "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT10M"}},
        },
    }
})


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _status(cc, token):
    return cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]


def _gate_waiting(cfn, stack_name):
    """Whether the held stack's WaitCondition exists and waits for its signal."""
    try:
        detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Gate")
    except ClientError:
        return False
    return detail["StackResourceDetail"].get("ResourceStatus") == "CREATE_IN_PROGRESS"


def _release(ctx, cfn, stack_name):
    """Signal the WaitCondition, ending the window the check holds."""
    _poll_until(
        lambda: _gate_waiting(cfn, stack_name), bool,
        description=f"the WaitCondition of {stack_name} waiting for its signal",
    )
    cfn.signal_resource(
        StackName=stack_name, LogicalResourceId="Gate", UniqueId="sim2real-release", Status="SUCCESS"
    )


def _drop_stack(ctx, cfn, stack_name):
    """Teardown: release the gate if the stack still waits, delete it, and wait it out."""
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as err:
        if "does not exist" in err.response["Error"].get("Message", ""):
            return
        raise
    if stacks[0]["StackStatus"] == "CREATE_IN_PROGRESS" and _gate_waiting(cfn, stack_name):
        _release(ctx, cfn, stack_name)
    stack_id = stacks[0]["StackId"]
    cfn.delete_stack(StackName=stack_id)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"],
        lambda s: s == "DELETE_COMPLETE",
        timeout_s=300, interval_s=5.0, description=f"stack {stack_name} reaching DELETE_COMPLETE",
    )


def _start_held_create(ctx, cc, cfn, stack_name):
    """Start the held create; return (token, identifier) once the request names its stack."""
    started = cc.create_resource(
        TypeName=STACK_TYPE,
        DesiredState=json.dumps({"StackName": stack_name, "TemplateBody": HELD_TEMPLATE}),
    )
    token = started["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _drop_stack(ctx, cfn, stack_name))
    assert started["ProgressEvent"]["OperationStatus"] in ("PENDING", "IN_PROGRESS"), started
    event = _poll_until(
        lambda: _status(cc, token),
        lambda e: e.get("Identifier") or e["OperationStatus"] in TERMINAL_STATUSES,
        description=f"create request {token} naming its stack",
    )
    assert event["OperationStatus"] == "IN_PROGRESS", (
        f"the held create left IN_PROGRESS before the check released it: {event!r}"
    )
    return token, event["Identifier"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
