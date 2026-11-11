"""pass-context-object-shape-excludes-retry-count-and-task."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pass-context-object-shape-excludes-retry-count-and-task"
GROUP = 'context_object'
SERVICES = ['stepfunctions']

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _parse_iso_z(stamp):
    assert isinstance(stamp, str) and stamp.endswith("Z"), f"{stamp!r} is not ISO-8601 Z"
    return datetime.fromisoformat(stamp[:-1] + "+00:00").astimezone(timezone.utc)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Pass state's full $$ context object carries Execution{Id, Name, Input, StartTime},
    State{Name, EnteredTime} and StateMachine{Id, Name}; it carries no State.RetryCount
    (the state was never retried) and no Task key (Pass invokes no task).
    """
    role_arn = _create_sfn_role(ctx)
    sm_name = ctx.unique_name("sim2real-behav-sfnctx-")
    definition = {
        "StartAt": "Ctx",
        "States": {
            "Ctx": {"Type": "Pass", "Parameters": {"ctx.$": "$$"}, "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn, sm_name)

    exec_name = ctx.unique_name("sim2real-behav-ctxexec-")
    input_data = {"marker": ctx.unique_name("m-")}
    exe = _run_execution(ctx, sm_arn, exec_name, input_data)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    sfn_ctx = out["ctx"]

    assert set(sfn_ctx) == {"Execution", "State", "StateMachine"}, (
        f"top-level $$ keys were {sorted(sfn_ctx)!r}, expected exactly Execution/State/StateMachine "
        f"-- in particular no 'Task' key outside a Task state"
    )

    execution = sfn_ctx["Execution"]
    assert execution["Id"] == exe["executionArn"], (
        f"Execution.Id {execution['Id']!r} != DescribeExecution's executionArn {exe['executionArn']!r}"
    )
    assert execution["Name"] == exec_name, f"Execution.Name {execution['Name']!r} != {exec_name!r}"
    assert execution["Input"] == input_data, (
        f"Execution.Input {execution['Input']!r} != the execution's own input {input_data!r}"
    )
    start_time = _parse_iso_z(execution["StartTime"])
    assert start_time == exe["startDate"], (
        f"Execution.StartTime {execution['StartTime']!r} parses to {start_time!r}, which "
        f"disagrees with DescribeExecution's startDate {exe['startDate']!r}"
    )

    state = sfn_ctx["State"]
    assert state["Name"] == "Ctx", f"State.Name {state['Name']!r} != 'Ctx'"
    _parse_iso_z(state["EnteredTime"])
    assert "RetryCount" not in state, (
        f"State carried a RetryCount of {state.get('RetryCount')!r} though 'Ctx' was never retried"
    )

    state_machine = sfn_ctx["StateMachine"]
    assert state_machine["Id"] == sm_arn, f"StateMachine.Id {state_machine['Id']!r} != {sm_arn!r}"
    assert state_machine["Name"] == sm_name, (
        f"StateMachine.Name {state_machine['Name']!r} != {sm_name!r}"
    )


def _create_sfn_role(ctx):
    """A bare execution role: a single Pass state calls no AWS API on the customer's behalf."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnctx-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn context-object execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn, name):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
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


def _run_execution(ctx, sm_arn, exec_name, input_data, *, timeout_s=90.0):
    """Start one execution and poll DescribeExecution every 2s until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps(input_data)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
