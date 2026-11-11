"""choice-input-path-scopes-comparator-variable-resolution."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-input-path-scopes-comparator-variable-resolution"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A throwaway execution role, so the check assumes no pre-existing estate."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine is what makes this correct, and this sleep only makes it cheaper.
    time.sleep(2)
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choice-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choice"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_execution(ctx, sm_arn, input_data, *, timeout_s=60):
    """Start one execution, wait for a terminal status, return (describe, entered_state_names)."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(
            f"execution for input {input_data!r} never reached a terminal status within "
            f"{timeout_s}s; last describe was {desc!r}"
        )
    return desc, _entered_states(ctx, exec_arn)


def _entered_states(ctx, exec_arn):
    """Every state name the execution ENTERED, in order, from the paginated history."""
    sfn = ctx.client("stepfunctions")
    events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


def _choice_states(*, input_path):
    """The same one-rule Choice machine, with or without an InputPath on the Choice state."""
    route = {
        "Type": "Choice",
        "Choices": [{"Variable": "$.v", "NumericGreaterThan": 10, "Next": "Big"}],
        "Default": "Small",
    }
    if input_path is not None:
        route["InputPath"] = input_path
    return {
        "StartAt": "Route",
        "States": {
            "Route": route,
            "Big": {"Type": "Pass", "Result": "big", "End": True},
            "Small": {"Type": "Pass", "Result": "small", "End": True},
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Choice state's InputPath rebases its rules' Variable paths: `$.v` reads the filtered v.

    Inputs where outer and inner v disagree route by the inner v; a machine without InputPath
    routes the same input by the outer v.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-inputpath-params.html
    """
    role_arn = _execution_role(ctx)
    filtered_arn = _create_state_machine(ctx, _choice_states(input_path="$.inner"), role_arn)

    cases = [
        (
            {"v": 0, "inner": {"v": 50}},
            "big",
            "Big",
            "the INNER v (50) satisfies NumericGreaterThan:10 while the outer v (0) does not, so "
            "evaluating against the unfiltered input would wrongly take Small",
        ),
        (
            {"v": 99, "inner": {"v": 1}},
            "small",
            "Small",
            "the INNER v (1) fails NumericGreaterThan:10 while the outer v (99) satisfies it, so "
            "the top-level field must have no influence on the branch at all",
        ),
    ]

    for input_data, expected_output, expected_state, why in cases:
        desc, entered = _run_execution(ctx, filtered_arn, input_data)
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} must succeed; both branches are Pass states, so a failure "
            f"here means the rebased path did not resolve. Got status={desc.get('status')} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert _output(desc) == expected_output, (
            f"with InputPath '$.inner', input {input_data!r} routed to {_output(desc)!r}, "
            f"expected {expected_output!r} -- {why}"
        )
        assert entered == ["Route", expected_state], (
            f"with InputPath '$.inner', input {input_data!r} must enter "
            f"['Route', {expected_state!r}]; history entered {entered!r} -- {why}"
        )

    # Control: without InputPath the same input takes the other branch, so "Small" above is
    # caused by the filter, not by the input.
    unfiltered_arn = _create_state_machine(ctx, _choice_states(input_path=None), role_arn)
    contradictory = {"v": 99, "inner": {"v": 1}}
    desc, entered = _run_execution(ctx, unfiltered_arn, contradictory)
    assert desc["status"] == "SUCCEEDED", (
        f"the no-InputPath control must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert _output(desc) == "big", (
        f"without InputPath the very same input {contradictory!r} must evaluate $.v against the "
        f"top-level document and route to Big; got {_output(desc)!r}. This is what makes the "
        f"filtered machine's 'small' attributable to InputPath rather than to the input."
    )
    assert entered == ["Route", "Big"], (
        f"the no-InputPath control must enter ['Route', 'Big'], history entered {entered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
