"""deep-sfn-language-format-absent-path-argument-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-format-absent-path-argument-rejected"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _machine(fmt):
    return {
        "StartAt": "Fmt",
        "States": {
            "Fmt": {"Type": "Pass", "Parameters": {"s.$": fmt}, "Next": "Done"},
            "Done": {"Type": "Pass", "End": True},
        },
    }


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """States.Format whose argument path is absent from the input fails the execution with
    States.Runtime, whose cause names the Format call and quotes the input it ran against;
    the well-formed control machine substitutes both arguments and succeeds.
    """
    role = _create_sfn_role(ctx)
    good_fmt = "States.Format('{}-{}', $.a, $.b)"
    bad_fmt = "States.Format('{}-{}', $.a, $.missing)"
    good_arn = _create_state_machine(ctx, _machine(good_fmt), role)
    bad_arn = _create_state_machine(ctx, _machine(bad_fmt), role)

    good = _run_execution(ctx, good_arn, {"a": "a", "b": "b"})
    assert good["status"] == "SUCCEEDED", (
        f"control Format must succeed, got {good['status']!r} error={good.get('error')!r} "
        f"cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]).get("s") == "a-b", (
        f"substituting both present paths must yield 'a-b', got {good.get('output')!r}"
    )

    bad_input = {"a": "a"}
    bad = _run_execution(ctx, bad_arn, bad_input)
    assert bad["status"] == "FAILED", (
        f"a Format whose argument path is absent from the input must fail the execution, "
        f"got {bad['status']!r} output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    entered_id = _entered_event_id(ctx, bad["executionArn"], "Fmt")
    expected_cause = (
        f"An error occurred while executing the state 'Fmt' (entered at the event id "
        f"#{entered_id}). The function '{bad_fmt}' had the following error: The JsonPath "
        f"argument for the field '$.missing' could not be found in the input "
        f"'{json.dumps(bad_input)}'"
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert bad.get("output") is None, (
        f"a Format over an absent path produced output {bad.get('output')!r}"
    )
    events = _history(ctx, bad["executionArn"])
    assert "Done" not in _entered(events), (
        f"the next state was entered after a failed Format: {_entered(events)!r}"
    )


def _create_sfn_role(ctx):
    """An execution role this check owns. Pass machines call no AWS API on the customer's
    behalf, but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=90.0):
    """Start one execution and poll DescribeExecution every 2s until it is terminal."""
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


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _entered_event_id(ctx, exec_arn, state_name):
    """The history event id at which ``state_name`` was entered."""
    for e in _history(ctx, exec_arn):
        if e["type"].endswith("StateEntered") and e["stateEnteredEventDetails"]["name"] == state_name:
            return e["id"]
    raise AssertionError(f"no StateEntered event for {state_name!r} in the history of {exec_arn!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
