"""jsonata-variable-scope-nested-map-parallel-boundaries."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-variable-scope-nested-map-parallel-boundaries"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Outer JSONata variables are readable two Map/Parallel levels down and their name may be
    reused once that scope exits; reassigning an outer name inside a nested scope is rejected at
    create, while reading a nested or sibling-branch variable from outside its scope fails at run.
    """
    role_arn = _create_sfn_role(ctx)

    _check_nested_read_and_name_reuse(ctx, role_arn)
    _check_duplicate_variable_name_rejected(ctx, role_arn)
    _check_inner_scope_invisible_outside(ctx, role_arn)
    _check_cross_branch_reference_undefined(ctx, role_arn)


def _check_nested_read_and_name_reuse(ctx, role_arn):
    """A variable assigned at the outer scope is visible inside a Parallel nested two levels
    inside a Map (Map -> ItemProcessor -> Parallel branch), and once that Map state has exited,
    the outer scope may assign a new variable reusing the same name with no conflict."""
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "SeedOuter",
        "States": {
            "SeedOuter": {"Type": "Pass", "Assign": {"Shared": "outer-seed"}, "Next": "Level1Map"},
            "Level1Map": {
                "Type": "Map",
                "Items": [1, 2],
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Level2Parallel",
                    "States": {
                        "Level2Parallel": {
                            "Type": "Parallel",
                            "Branches": [{
                                "StartAt": "ReadOuterFromLevel2",
                                "States": {"ReadOuterFromLevel2": {
                                    "Type": "Pass", "Output": "{% $Shared & '-level2' %}", "End": True,
                                }},
                            }],
                            "End": True,
                        },
                    },
                },
                "Next": "ReuseSharedAtOuter",
            },
            "ReuseSharedAtOuter": {
                "Type": "Pass", "Assign": {"Shared": "reused-at-outer"}, "Next": "ConfirmReuse",
            },
            "ConfirmReuse": {"Type": "Pass", "Output": "{% $Shared %}", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exe = _run_execution(ctx, sm_arn, {})
    assert exe["status"] == "SUCCEEDED", (
        f"nested two-level read of an outer variable must succeed, got {exe['status']!r} "
        f"error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    assert json.loads(exe["output"]) == "reused-at-outer", (
        f"the outer scope's reassignment after the Map exited must stick; got {exe['output']!r}"
    )
    events = _history(ctx, exe["executionArn"])
    level2_outputs = [
        json.loads(e["stateExitedEventDetails"]["output"]) for e in events
        if e.get("stateExitedEventDetails", {}).get("name") == "ReadOuterFromLevel2"
    ]
    assert level2_outputs == ["outer-seed-level2", "outer-seed-level2"], (
        f"each Map iteration's nested Parallel branch must read the pre-reuse outer value; got "
        f"{level2_outputs!r}"
    )


def _check_duplicate_variable_name_rejected(ctx, role_arn):
    """Assigning a nested scope's own variable using the SAME name as an outer-scope variable is
    rejected at CreateStateMachine time, before any machine exists."""
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "SeedOuter",
        "States": {
            "SeedOuter": {"Type": "Pass", "Assign": {"OuterScopeVar": "outer"}, "Next": "Level1Parallel"},
            "Level1Parallel": {
                "Type": "Parallel",
                "Branches": [{
                    "StartAt": "ReassignInner",
                    "States": {"ReassignInner": {
                        "Type": "Pass", "Assign": {"OuterScopeVar": "inner"}, "End": True,
                    }},
                }],
                "End": True,
            },
        },
    }
    code, message = _create_error(ctx, definition, role_arn)
    assert code == "InvalidDefinition", (
        f"reassigning an outer variable's name inside a nested scope must be rejected at create, "
        f"got {code!r}: {message!r}"
    )
    assert message == (
        "Invalid State Machine Definition: 'DUPLICATE_VARIABLE_NAME: The variable name "
        "'OuterScopeVar' was already defined in a parent scope. at "
        "/States/Level1Parallel/Branches[0]/States/ReassignInner/Assign/OuterScopeVar'"
    ), f"unexpected InvalidDefinition message {message!r}"


def _check_inner_scope_invisible_outside(ctx, role_arn):
    """A variable a Map's ItemProcessor assigns is accepted by CreateStateMachine when read by a
    state outside the Map, but every execution fails: the variable was never in the outer scope."""
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Level1Map",
        "States": {
            "Level1Map": {
                "Type": "Map",
                "Items": [1, 2],
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "AssignInner",
                    "States": {"AssignInner": {
                        "Type": "Pass", "Assign": {"InnerVar": "inner"}, "End": True,
                    }},
                },
                "Next": "ReadInnerVar",
            },
            "ReadInnerVar": {"Type": "Pass", "Output": "{% $InnerVar %}", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exe = _run_execution(ctx, sm_arn, {})
    assert exe["status"] == "FAILED", (
        f"reading a Map-inner-only variable from outside the Map must fail every execution, got "
        f"{exe['status']!r} output={exe.get('output')!r}"
    )
    assert exe.get("error") == "States.QueryEvaluationError", (
        f"expected error 'States.QueryEvaluationError', got {exe.get('error')!r} "
        f"cause={exe.get('cause')!r}"
    )
    entered_id = _entered_event_id(_history(ctx, exe["executionArn"]), "ReadInnerVar")
    assert exe.get("cause") == (
        f"An error occurred while executing the state 'ReadInnerVar' (entered at the event id "
        f"#{entered_id}). The JSONata expression '$InnerVar' specified for the field 'Output' "
        f"returned nothing (undefined)."
    ), f"unexpected inner-variable-outside-Map cause {exe.get('cause')!r}"


def _check_cross_branch_reference_undefined(ctx, role_arn):
    """A variable one Parallel branch assigns is accepted by CreateStateMachine when a sibling
    branch reads it, but the reading branch fails at runtime: branches are independent scopes."""
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Level1Parallel",
        "States": {
            "Level1Parallel": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "AssignBranchVar", "States": {"AssignBranchVar": {
                        "Type": "Pass", "Assign": {"BranchVar": "b1"}, "End": True,
                    }}},
                    {"StartAt": "ReadBranchVar", "States": {"ReadBranchVar": {
                        "Type": "Pass", "Output": "{% $BranchVar %}", "End": True,
                    }}},
                ],
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exe = _run_execution(ctx, sm_arn, {})
    assert exe["status"] == "FAILED", (
        f"a sibling Parallel branch reading another branch's variable must fail every "
        f"execution, got {exe['status']!r} output={exe.get('output')!r}"
    )
    assert exe.get("error") == "States.QueryEvaluationError", (
        f"expected error 'States.QueryEvaluationError', got {exe.get('error')!r} "
        f"cause={exe.get('cause')!r}"
    )
    entered_id = _entered_event_id(_history(ctx, exe["executionArn"]), "ReadBranchVar")
    assert exe.get("cause") == (
        f"An error occurred while executing the state 'ReadBranchVar' (entered at the event id "
        f"#{entered_id}). The JSONata expression '$BranchVar' specified for the field 'Output' "
        f"returned nothing (undefined)."
    ), f"unexpected cross-branch cause {exe.get('cause')!r}"


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx):
    """An execution role this check owns, shared by every sibling machine below: every state is
    a Pass, Map or Parallel, so no permissions policy is needed."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnvarscope-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn variable-scope check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-varscope"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnvarscope-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-varscope"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn


def _create_error(ctx, definition, role_arn):
    """The (code, message) CreateStateMachine raised. A create that SUCCEEDS is torn down and
    failed: this helper is only used where the definition is refused."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnvarscope-sm-")
    try:
        arn = sfn.create_state_machine(
            name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
            tags=[{"key": "sim2real", "value": "sfn-varscope"}],
        )["stateMachineArn"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    raise AssertionError(f"CreateStateMachine accepted a definition it rejects: {arn!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered_event_id(events, state_name):
    """The history event id of `state_name`'s StateEntered event: the number a Runtime cause
    names, read back from the same execution rather than assumed."""
    matches = [e["id"] for e in events
               if e.get("stateEnteredEventDetails", {}).get("name") == state_name]
    assert len(matches) == 1, (
        f"expected exactly one StateEntered for {state_name!r}, found {matches!r}"
    )
    return matches[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
