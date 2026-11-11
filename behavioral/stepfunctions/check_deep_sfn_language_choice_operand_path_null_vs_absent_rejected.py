"""deep-sfn-language-choice-operand-path-null-vs-absent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-choice-operand-path-null-vs-absent-rejected"
GROUP = "choice_state"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Choice `*Path` comparator operand resolving to an explicit null fails States.Runtime with
    a distinct 'null input' cause, not the generic 'invalid value' cause an absent operand gets;
    the same machine with a present, non-null operand succeeds.
    """
    definition = {
        "StartAt": "C",
        "States": {
            "C": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.foo", "StringEqualsPath": "$.bar", "Next": "Matched"},
                ],
                "Default": "Fallback",
            },
            "Matched": {"Type": "Pass", "Result": "matched", "End": True},
            "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))

    good = _run_execution(ctx, sm_arn, {"foo": "x", "bar": "x"})
    assert good["status"] == "SUCCEEDED", (
        f"control: a present, non-null, matching operand must succeed, got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == "matched", f"control output was {good.get('output')!r}"

    null_run = _run_execution(ctx, sm_arn, {"foo": "x", "bar": None})
    assert null_run["status"] == "FAILED", (
        f"an operand path resolving to an explicit null must fail, got {null_run['status']!r} "
        f"output={null_run.get('output')!r}"
    )
    assert null_run.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {null_run.get('error')!r} cause={null_run.get('cause')!r}"
    )
    assert null_run.get("cause") == (
        "An error occurred while executing the state 'C' (entered at the event id #2). "
        "Null value provided at path '$.bar': Unable to compare with a null input."
    ), f"unexpected null-operand cause {null_run.get('cause')!r}"

    absent_run = _run_execution(ctx, sm_arn, {"foo": "x"})
    assert absent_run["status"] == "FAILED", (
        f"an operand path that does not resolve at all must fail, got {absent_run['status']!r} "
        f"output={absent_run.get('output')!r}"
    )
    assert absent_run.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {absent_run.get('error')!r} "
        f"cause={absent_run.get('cause')!r}"
    )
    assert absent_run.get("cause") == (
        "An error occurred while executing the state 'C' (entered at the event id #2). "
        "Invalid path '$.bar': The choice state's condition path references an invalid value."
    ), f"unexpected absent-operand cause {absent_run.get('cause')!r}"

    assert null_run["cause"] != absent_run["cause"], (
        "an explicit null operand and an absent operand are different failures and must not "
        f"collapse into one byte-identical cause; both said {null_run['cause']!r}"
    )

    for exec_desc in (null_run, absent_run):
        entered = _entered_names(_history(ctx, exec_desc["executionArn"]))
        assert "Matched" not in entered and "Fallback" not in entered, (
            f"a Choice runtime failure must never transition out of the state; entered {entered!r}"
        )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx):
    """An execution role this check owns. A Choice/Pass-only machine needs no permissions, but
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


def _entered_names(events):
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
