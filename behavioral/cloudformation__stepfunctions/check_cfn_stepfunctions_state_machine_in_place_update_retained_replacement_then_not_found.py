"""cfn-stepfunctions-state-machine-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stepfunctions-state-machine-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: DeleteStateMachine is asynchronous: the machine stays describable as DELETING for minutes.
#: The check grades DELETING or not-found within the first cap; teardown waits out the purge.
_DELETING_CAP_S = 60.0
_GONE_CAP_S = 600.0
_EXECUTION_CAP_S = 120.0
#: Every teardown shares one deadline, set by the first to run, inside the suite's cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Step Functions' refusal of a state machine that no longer exists.
_NOT_FOUND_CODE = "StateMachineDoesNotExist"
_NOT_FOUND_MESSAGE = "State Machine Does Not Exist: '{arn}'"
#: Step Functions' refusal to start an execution of a state machine that is being deleted.
_DELETING_CODE = "StateMachineDeleting"
_DELETING_MESSAGE = "State Machine is being deleted: '{arn}'"


def _definition(answer: str) -> dict:
    return {
        "Comment": "A Pass state that returns a fixed result",
        "StartAt": "Answer",
        "States": {"Answer": {"Type": "Pass", "Result": {"answer": answer}, "End": True}},
    }


def _template(machine_name: str, answer: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "Machine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    # StateMachineName is create-only, so changing it replaces the state machine.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "StateMachineName": machine_name,
                        "StateMachineType": "STANDARD",
                        "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                        "DefinitionString": json.dumps(_definition(answer)),
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                "MachineArn": {"Value": {"Ref": "Machine"}},
                "MachineName": {"Value": {"Fn::GetAtt": ["Machine", "Name"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation state machine reads back, updates in place and survives replacement.

    An execution SUCCEEDS with the Pass result; a definition change keeps the machine, a name change
    under UpdateReplacePolicy Retain keeps the old one running; a deleted one refuses executions.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachine.html
    """
    cfn = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    first = ctx.unique_name("sim2real-cfnsm-a-")
    second = ctx.unique_name("sim2real-cfnsm-b-")
    stack_name = ctx.unique_name("sim2real-cfnsm-stack-")
    ref = {"stack": stack_name}
    machines: dict[str, str] = {}
    teardown: dict = {}

    # Teardown runs in reverse: the stack first, then the retained machine and both purges.
    # The replaced state machine is retained, so it outlives the stack and needs its own delete.
    ctx.on_cleanup(lambda: _delete_machine(sfn, machines.get("second"), teardown))
    ctx.on_cleanup(lambda: _delete_machine(sfn, machines.get("first"), teardown))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Step Functions' view, and an execution
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "one"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    # The partition is the StackId's own, so the expected ARNs hold in every partition.
    partition = ref["stack"].split(":")[1]
    machines["first"] = f"arn:{partition}:states:{ctx.region}:{ctx.account}:stateMachine:{first}"
    machines["second"] = f"arn:{partition}:states:{ctx.region}:{ctx.account}:stateMachine:{second}"
    first_arn, second_arn = machines["first"], machines["second"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    assert _physical_ids(cfn, ref["stack"])["Machine"] == first_arn, (
        f"the state machine's physical id must be its ARN {first_arn!r}"
    )
    assert (outputs["MachineArn"], outputs["MachineName"]) == (first_arn, first), (
        f"Ref and GetAtt Name: {outputs!r}"
    )
    _assert_machine(sfn, first_arn, first, outputs["RoleArn"], "one")
    _assert_execution(ctx, sfn, first_arn, "one")

    # ---- 2. in-place: a new definition, the same state machine
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, "two"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Machine"] == first_arn, (
        "an in-place update keeps the state machine"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Machine"), first_arn, "Machine")
    _assert_machine(sfn, first_arn, first, outputs["RoleArn"], "two")
    _assert_execution(ctx, sfn, first_arn, "two", previous="one")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new state machine, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, "three"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Machine"] == second_arn, (
        f"the stack must track the replacement {second_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Machine"), first_arn, second_arn, "Machine"
    )
    assert _outputs(stack)["MachineArn"] == second_arn, f"Ref after replacement: {stack!r}"
    _assert_machine(sfn, second_arn, second, outputs["RoleArn"], "three")
    _assert_execution(ctx, sfn, second_arn, "three")
    _assert_machine(sfn, first_arn, first, outputs["RoleArn"], "two")
    _assert_execution(ctx, sfn, first_arn, "two")

    # ---- 4. delete: the stack's state machine is DELETING (refusing executions) or gone
    _delete_stack(ctx, cfn, ref["stack"])
    state = _poll_deleting(ctx, sfn, second_arn)
    if state == "DELETING":
        got = _error(
            lambda: sfn.start_execution(
                stateMachineArn=second_arn, name=ctx.unique_name("run-"), input="{}"
            )
        )
        want = (_DELETING_CODE, _DELETING_MESSAGE.format(arn=second_arn))
        assert got == want, f"StartExecution on the DELETING {second} answered {got!r}"
    else:
        want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(arn=second_arn))
        assert state == want, f"DescribeStateMachine after the stack delete answered {state!r}"


def _poll_deleting(ctx, sfn, arn: str):
    """Poll DescribeStateMachine until *arn* is DELETING ("DELETING") or gone (code, message).

    DeleteStateMachine is asynchronous, so ACTIVE may linger briefly after DELETE_COMPLETE.
    """
    timeout = _budget_s(ctx, _DELETING_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        try:
            described = sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == _NOT_FOUND_CODE:
                return err.get("Code"), err.get("Message")
            raise
        if described.get("status") == "DELETING":
            return "DELETING"
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {arn} was {described.get('status')}")
            raise AssertionError(
                f"{arn} neither DELETING nor gone after {timeout:.0f}s: {described.get('status')!r}"
            )
        time.sleep(_POLL_S)


def _assert_machine(sfn, arn: str, name: str, role_arn: str, answer: str) -> None:
    """DescribeStateMachine reports the template's state machine exactly."""
    described = sfn.describe_state_machine(stateMachineArn=arn)
    got = {k: described.get(k) for k in ("stateMachineArn", "name", "type", "roleArn", "status")}
    want = {
        "stateMachineArn": arn,
        "name": name,
        "type": "STANDARD",
        "roleArn": role_arn,
        "status": "ACTIVE",
    }
    assert got == want, f"DescribeStateMachine {arn}: {got!r}, expected {want!r}"
    assert json.loads(described["definition"]) == _definition(answer), (
        f"{name} definition {described['definition']!r}, expected the Pass result {answer!r}"
    )


def _assert_execution(ctx, sfn, arn: str, answer: str, *, previous: str | None = None) -> None:
    """An execution of the state machine SUCCEEDS with the Pass state's result as its output.

    Executions started shortly after an update may still run the *previous* definition, so an
    execution answering *previous* is followed by a new one until the cap.
    """
    timeout = _budget_s(ctx, _EXECUTION_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        execution_arn, described = _execute(ctx, sfn, arn, deadline, timeout)
        stale = previous is not None and described["status"] == "SUCCEEDED"
        if not (stale and json.loads(described["output"]) == {"answer": previous}):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {arn} still ran the old definition")
            raise AssertionError(
                f"executions of {arn} still answer {previous!r} after {timeout:.0f}s: {described!r}"
            )
        time.sleep(_POLL_S)
    assert described["status"] == "SUCCEEDED", f"execution {execution_arn} ended {described!r}"
    assert json.loads(described["output"]) == {"answer": answer}, (
        f"execution {execution_arn} output {described['output']!r}, expected answer {answer!r}"
    )


def _execute(ctx, sfn, arn: str, deadline: float, timeout: float) -> tuple[str, dict]:
    """Start an execution and poll it until it leaves RUNNING: its ARN and DescribeExecution."""
    execution_arn = sfn.start_execution(
        stateMachineArn=arn,
        name=ctx.unique_name("run-"),
        input=json.dumps({"in": 1}),
    )["executionArn"]
    while True:
        described = sfn.describe_execution(executionArn=execution_arn)
        if described["status"] != "RUNNING":
            return execution_arn, described
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {execution_arn} was RUNNING")
            raise AssertionError(f"{execution_arn} still RUNNING after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _delete_machine(sfn, arn: str | None, teardown: dict) -> None:
    """Teardown: delete the state machine (if its ARN is known), wait until it is gone."""
    if arn is None:
        return
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise
        return
    _wait_error(
        None,
        lambda: sfn.describe_state_machine(stateMachineArn=arn),
        _NOT_FOUND_CODE,
        f"state machine {arn}",
        teardown,
    )


def _teardown_deadline(teardown: dict) -> float:
    """The one deadline every teardown shares, fixed when the first of them asks for it."""
    return teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)


def _timeout(ctx, cap_s, teardown: dict | None) -> float:
    """A wait's timeout: the shared teardown deadline's remainder in a teardown, else _budget_s."""
    if teardown is not None:
        return max(1.0, _teardown_deadline(teardown) - time.monotonic())
    return _budget_s(ctx, cap_s)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    if ctx is None:
        return False
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _timeout(ctx, _STACK_CAP_S, teardown)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str, teardown: dict | None = None):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _timeout(ctx, _GONE_CAP_S, teardown)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict, teardown: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits end at the deadline every teardown shares.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], teardown)
    _delete_stack(None, cfn, stack["StackId"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
