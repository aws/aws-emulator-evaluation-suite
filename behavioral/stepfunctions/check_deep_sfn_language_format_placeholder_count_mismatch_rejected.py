"""deep-sfn-language-format-placeholder-count-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-format-placeholder-count-mismatch-rejected"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']


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
    """States.Format with fewer arguments than '{}' placeholders is accepted by CreateStateMachine
    but fails each execution with States.Runtime naming States.Format; the well-formed control
    machine substitutes positionally ('a-b').
    """
    role = _create_sfn_role(ctx)
    good_arn = _create_state_machine(ctx, _machine("States.Format('{}-{}', $.a, $.b)"), role)
    bad_arn = _create_state_machine(ctx, _machine("States.Format('{}-{}', $.a)"), role)

    good = _run_execution(ctx, good_arn, {"a": "a", "b": "b"})
    assert good["status"] == "SUCCEEDED", (
        f"control Format must succeed, got {good['status']!r} error={good.get('error')!r} "
        f"cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]).get("s") == "a-b", (
        f"positional substitution must yield 'a-b', got {good.get('output')!r}"
    )

    bad = _run_execution(ctx, bad_arn, {"a": "a", "b": "b"})
    assert bad["status"] == "FAILED", (
        f"a Format with too few arguments must fail the execution, got {bad['status']!r} "
        f"output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert "States.Format" in (bad.get("cause") or ""), (
        f"the cause must name States.Format, got {bad.get('cause')!r}"
    )
    assert bad.get("output") is None, f"a mismatched Format produced output {bad.get('output')!r}"
    events = _history(ctx, bad["executionArn"])
    assert "Done" not in _entered(events), (
        f"the next state was entered after a failed Format: {_entered(events)!r}"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
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

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
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
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


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
        time.sleep(1)
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


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
