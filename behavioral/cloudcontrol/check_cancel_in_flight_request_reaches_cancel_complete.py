"""cancel-in-flight-request-reaches-cancel-complete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-in-flight-request-reaches-cancel-complete"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol', 'cloudformation']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelResourceRequest on an IN_PROGRESS create drives it to CANCEL_COMPLETE (never SUCCESS)
    with the user-cancellation StatusMessage; re-cancelling echoes CANCEL_COMPLETE."""
    cc = ctx.client("cloudcontrol")
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cc-cancel-")
    token, _ = _start_held_create(ctx, cc, cfn, stack_name)

    cancel_event = cc.cancel_resource_request(RequestToken=token)["ProgressEvent"]
    assert cancel_event["RequestToken"] == token, cancel_event
    assert cancel_event["Operation"] == "CREATE", cancel_event
    assert cancel_event["OperationStatus"] in ("CANCEL_IN_PROGRESS", "CANCEL_COMPLETE"), cancel_event

    final = _poll_until(
        lambda: _status(cc, token), lambda e: e["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=180, interval_s=3.0, description=f"cancelled request {token} terminating",
    )
    assert final["OperationStatus"] == "CANCEL_COMPLETE", final
    assert final.get("StatusMessage") == "User Initialized the Cancellation", (
        f"expected the cancelled request's StatusMessage 'User Initialized the Cancellation', "
        f"got {final.get('StatusMessage')!r}"
    )

    # Re-cancelling a CANCEL_COMPLETE request is accepted and echoes the terminal state.
    recancel = cc.cancel_resource_request(RequestToken=token)["ProgressEvent"]
    assert recancel["RequestToken"] == token, recancel
    assert recancel["OperationStatus"] == "CANCEL_COMPLETE", recancel


STACK_TYPE = "AWS::CloudFormation::Stack"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
# The WaitCondition waits for a signal only this check sends, so the create request stays
# IN_PROGRESS until released, independent of provisioning speed.
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
