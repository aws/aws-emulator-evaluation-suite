"""changeset-arn-resolves-to-correct-stack-without-stack-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-arn-resolves-to-correct-stack-without-stack-name"
GROUP = "change_sets"
SERVICES = ["cloudformation"]


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _queue_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue"}},
    })


def _wait_change_set_ready(cf, cs_arn, timeout_s=120):
    """Poll the change set to a terminal status (CREATE_COMPLETE or FAILED); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.describe_change_set(ChangeSetName=cs_arn)
        if resp["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"change set {cs_arn} did not reach a terminal status within {timeout_s}s "
                f"(last={resp['Status']!r})"
            )
        time.sleep(2)


def _wait_stack_terminal(cf, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(3)
    raise AssertionError(f"stack {name} terminal not reached within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected a ClientError but the call succeeded")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CREATE change set's ARN alone resolves to its own stack when another stack has a same-named
    change set; executing it by ARN leaves the sibling untouched, and the deleted sibling is gone.
    """
    cf = ctx.client("cloudformation")

    first_stack = ctx.unique_name("sim2real-behav-csarn1-")
    second_stack = ctx.unique_name("sim2real-behav-csarn2-")
    cs_name = "sim2real-shared-cs-name"

    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, first_stack))
    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, second_stack))

    first = cf.create_change_set(
        StackName=first_stack, ChangeSetName=cs_name, ChangeSetType="CREATE",
        TemplateBody=_queue_template(),
    )
    second = cf.create_change_set(
        StackName=second_stack, ChangeSetName=cs_name, ChangeSetType="CREATE",
        TemplateBody=_queue_template(),
    )
    first_arn = first["Id"]
    second_arn = second["Id"]
    assert first_arn != second_arn, (
        f"two distinct CreateChangeSet calls returned the same Id {first_arn!r}"
    )

    first_ready = _wait_change_set_ready(cf, first_arn)
    second_ready = _wait_change_set_ready(cf, second_arn)
    assert first_ready["Status"] == "CREATE_COMPLETE", (
        f"first change set status {first_ready['Status']!r}, reason "
        f"{first_ready.get('StatusReason')!r}"
    )
    assert second_ready["Status"] == "CREATE_COMPLETE", (
        f"second change set status {second_ready['Status']!r}, reason "
        f"{second_ready.get('StatusReason')!r}"
    )

    # The ARN alone -- same ChangeSetName on both -- must resolve to the stack it was created
    # against, not to whichever same-named change set happens to be found first.
    resolved_second = cf.describe_change_set(ChangeSetName=second_arn)
    assert resolved_second["StackName"] == second_stack, (
        f"describe_change_set({second_arn!r}) resolved StackName="
        f"{resolved_second['StackName']!r}, expected {second_stack!r}"
    )
    resolved_first = cf.describe_change_set(ChangeSetName=first_arn)
    assert resolved_first["StackName"] == first_stack, (
        f"describe_change_set({first_arn!r}) resolved StackName="
        f"{resolved_first['StackName']!r}, expected {first_stack!r}"
    )

    cf.execute_change_set(ChangeSetName=second_arn)
    status = _wait_stack_terminal(cf, second_stack)
    assert status == "CREATE_COMPLETE", (
        f"second stack status after executing its change set by ARN is {status!r}"
    )
    resource = cf.describe_stack_resource(
        StackName=second_stack, LogicalResourceId="Queue"
    )["StackResourceDetail"]
    assert resource["ResourceStatus"] == "CREATE_COMPLETE", (
        f"Queue resource status is {resource['ResourceStatus']!r}, expected CREATE_COMPLETE"
    )
    executed = cf.describe_change_set(ChangeSetName=second_arn)
    assert executed["ExecutionStatus"] == "EXECUTE_COMPLETE", (
        f"second change set ExecutionStatus is {executed['ExecutionStatus']!r}, expected "
        "EXECUTE_COMPLETE"
    )

    # The sibling stack and its own change set were never touched by the execute above.
    first_stack_status = cf.describe_stacks(StackName=first_stack)["Stacks"][0]["StackStatus"]
    assert first_stack_status == "REVIEW_IN_PROGRESS", (
        f"first stack status is {first_stack_status!r}, expected REVIEW_IN_PROGRESS -- it must "
        "not have been affected by executing the second change set"
    )
    first_cs_status = cf.describe_change_set(ChangeSetName=first_arn)
    assert first_cs_status["ExecutionStatus"] == "AVAILABLE", (
        f"first change set ExecutionStatus is {first_cs_status['ExecutionStatus']!r}, expected "
        "AVAILABLE"
    )

    cf.delete_change_set(ChangeSetName=first_arn)
    code, message = _error(lambda: cf.describe_change_set(ChangeSetName=first_arn))
    # Real AWS returns the bare code 'ChangeSetNotFound'; the Smithy model names the shape
    # 'ChangeSetNotFoundException'.
    assert code == "ChangeSetNotFound", (
        f"describe_change_set on the deleted change set raised {code!r}, expected "
        "ChangeSetNotFound"
    )
    assert message == f"ChangeSet [{first_arn}] does not exist", (
        f"describe_change_set on the deleted change set answered {message!r}"
    )


def _delete_stack_if_present(cf, stack_name: str) -> None:
    try:
        cf.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return
        raise
    cf.delete_stack(StackName=stack_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
