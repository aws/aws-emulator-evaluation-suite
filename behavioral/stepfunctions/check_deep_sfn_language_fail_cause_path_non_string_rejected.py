"""deep-sfn-language-fail-cause-path-non-string-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-fail-cause-path-non-string-rejected"
GROUP = "fail_state"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Fail state whose CausePath resolves to a number fails the execution with States.Runtime
    naming the value, rather than surfacing it as the cause; the same machine given a string
    surfaces it verbatim.
    """
    definition = {"StartAt": "F", "States": {"F": {
        "Type": "Fail", "CausePath": "$.c", "Error": "static.error"}}}
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))

    good = _run_execution(ctx, sm_arn, {"c": "a string cause"})
    assert good["status"] == "FAILED" and good.get("cause") == "a string cause", (
        f"control: a string CausePath must surface verbatim, got status={good['status']!r} "
        f"cause={good.get('cause')!r}"
    )
    assert good.get("error") == "static.error", f"control error was {good.get('error')!r}"

    bad = _run_execution(ctx, sm_arn, {"c": 5})
    assert bad["status"] == "FAILED", f"expected FAILED, got {bad['status']!r}"
    assert bad.get("error") == "States.Runtime", (
        f"a numeric CausePath value must be refused with 'States.Runtime', got "
        f"{bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == (
        "An error occurred while executing the state 'F' (entered at the event id #2). "
        "The value referenced by CausePath must be a string, but the value was: 5"
    ), f"unexpected CausePath rejection cause {bad.get('cause')!r}"

    events = _history(ctx, bad["executionArn"])
    errors = [e["executionFailedEventDetails"].get("error") for e in events
              if e["type"] == "ExecutionFailed"]
    assert errors == ["States.Runtime"], (
        f"the numeric value must not become the execution's error; ExecutionFailed errors={errors!r}"
    )
    assert "static.error" != bad.get("error"), (
        "the static Error was emitted as though the Fail state had completed normally"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx):
    """An execution role this check owns. A Fail-only machine needs no permissions, but
    CreateStateMachine still requires a role Step Functions can assume."""
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
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
