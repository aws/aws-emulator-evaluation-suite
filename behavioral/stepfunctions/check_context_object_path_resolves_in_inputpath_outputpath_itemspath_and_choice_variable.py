"""context-object-path-resolves-in-inputpath-outputpath-itemspath-and-choice-variable."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "context-object-path-resolves-in-inputpath-outputpath-itemspath-and-choice-variable"
GROUP = "context_object"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _definition() -> dict:
    """Each state deliberately detaches `$` from the original input, so a path that still
    produces the right value must have come from `$$.Execution.Input`, not from `$`."""
    return {
        "StartAt": "Reshape",
        "States": {
            # $ becomes {"reshaped": true}; the original input survives only in $$.Execution.Input.
            "Reshape": {
                "Type": "Pass",
                "Parameters": {"reshaped": True},
                "Next": "PickPayloadFromContext",
            },
            # InputPath reaches past the reshaped $ into the context object's Execution.Input.
            "PickPayloadFromContext": {
                "Type": "Pass",
                "InputPath": "$$.Execution.Input.payload",
                "Next": "ChooseOnContext",
            },
            # $ is now just the payload sub-object, which carries no branchFlag; a Choice that
            # evaluated $.branchFlag would error "path not found" rather than route.
            "ChooseOnContext": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$$.Execution.Input.branchFlag",
                        "StringEquals": "go",
                        "Next": "MapOverContextItems",
                    }
                ],
                "Default": "UnexpectedBranch",
            },
            "UnexpectedBranch": {"Type": "Fail", "Error": "WrongBranch"},
            # ItemsPath iterates the context object's items, ignoring $ (still the payload).
            "MapOverContextItems": {
                "Type": "Map",
                "ItemsPath": "$$.Execution.Input.items",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Echo",
                    "States": {"Echo": {"Type": "Pass", "End": True}},
                },
                "ResultPath": "$.mapped",
                "Next": "SelectOutputFromContext",
            },
            # OutputPath replaces the entire result with a context-object read, discarding
            # everything Reshape/Map produced.
            "SelectOutputFromContext": {
                "Type": "Pass",
                "OutputPath": "$$.Execution.Input.trailer",
                "End": True,
            },
        },
    }


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_state_machine(ctx, role_arn: str):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-ctxpath-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_definition()),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last_err}")


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn: str) -> None:
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn: str) -> list:
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 90.0, interval_s: float = 2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InputPath, a Choice's Variable, a Map's ItemsPath and OutputPath each resolve
    `$$.Execution.Input.*` against the execution's original input, independent of the
    reshaped `$` each state actually carries, and route, iterate and filter accordingly."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    payload = {"keep": "yes"}
    items = [3, 5, 9]
    trailer = {"final": "value"}
    exec_input = {"payload": payload, "branchFlag": "go", "items": items, "trailer": trailer}
    exec_arn = _start(ctx, sm_arn, exec_input)
    desc = _wait_terminal(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"execution ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )
    output = json.loads(desc["output"])
    assert output == trailer, (
        f"OutputPath '$$.Execution.Input.trailer' should have replaced the whole result with "
        f"{trailer!r}, the execution output was {output!r}"
    )

    # The Map's own exit, read independently of the final OutputPath that later discards it:
    # proof ItemsPath '$$.Execution.Input.items' iterated the right array, not an empty/foreign $.
    history = _history(ctx, exec_arn)
    map_exits = [
        e
        for e in history
        if e["type"].endswith("StateExited")
        and e["stateExitedEventDetails"]["name"] == "MapOverContextItems"
    ]
    assert len(map_exits) == 1, f"expected exactly one MapOverContextItems exit, got {map_exits!r}"
    mapped = json.loads(map_exits[0]["stateExitedEventDetails"]["output"])["mapped"]
    assert mapped == items, (
        f"ItemsPath '$$.Execution.Input.items' should have iterated {items!r}, the Map produced "
        f"{mapped!r}"
    )

    # Negative control: branchFlag "stop" must route to Default via the context, not reach the
    # Map at all — proving ChooseOnContext read $$ and not the payload-only $.
    exec_arn2 = _start(ctx, sm_arn, {**exec_input, "branchFlag": "stop"})
    desc2 = _wait_terminal(ctx, exec_arn2)
    assert desc2["status"] == "FAILED", (
        f"the 'stop' execution ended {desc2['status']!r}, expected FAILED via UnexpectedBranch"
    )
    assert desc2.get("error") == "WrongBranch", (
        f"the 'stop' execution failed with error {desc2.get('error')!r}, expected 'WrongBranch'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
