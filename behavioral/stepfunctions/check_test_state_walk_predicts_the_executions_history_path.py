"""test-state-walk-predicts-the-executions-history-path."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-walk-predicts-the-executions-history-path"
GROUP = "definition_semantics"
SERVICES = ["stepfunctions"]

_TRUST = json.dumps(
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

_START = "Classify"
_DEFINITION = json.dumps(
    {
        "StartAt": _START,
        "States": {
            _START: {
                "Type": "Choice",
                "Choices": [{"Variable": "$.weight", "NumericGreaterThan": 10, "Next": "Heavy"}],
                "Default": "Light",
            },
            "Heavy": {
                "Type": "Pass",
                "Result": {"band": "heavy", "surcharge": 4},
                "ResultPath": "$.rating",
                "Next": "Settle",
            },
            "Light": {
                "Type": "Pass",
                "Result": {"band": "light", "surcharge": 0},
                "ResultPath": "$.rating",
                "Next": "Settle",
            },
            "Settle": {"Type": "Succeed"},
        },
    }
)
_EXECUTION_INPUT = json.dumps({"weight": 42, "parcel": "p1"})
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _undo(delete, *gone: str):
    """A cleanup whose delete raises unless the resource reports one of ``gone``."""

    def apply() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return apply


def _once_assumable(call, *, budget_s: float = 120.0):
    """``call()``, retrying while a freshly created role is not yet assumable by the service."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return call()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidArn") or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _test_one(sfn, role_arn: str, state: str, payload: str) -> dict:
    """TestState's answer for one state of the definition, fed ``payload`` as its input."""
    return _once_assumable(
        lambda: sfn.test_state(
            definition=_DEFINITION,
            stateName=state,
            input=payload,
            roleArn=role_arn,
            inspectionLevel="INFO",
        )
    )


def _walk(sfn, role_arn: str, payload: str) -> tuple[list[str], str]:
    """The state names TestState walks from the definition's StartAt, and the last state's output."""
    visited: list[str] = []
    state = _START
    while True:
        answer = _test_one(sfn, role_arn, state, payload)
        assert answer["status"] == "SUCCEEDED", (
            f"TestState on {state!r} reported {answer['status']!r}, "
            f"error {answer.get('error')!r}, cause {answer.get('cause')!r}"
        )
        visited.append(state)
        payload = answer["output"]
        following = answer.get("nextState") or ""
        if not following:
            return visited, payload
        assert len(visited) <= 8, f"the walk did not terminate; it visited {visited!r}"
        state = following


def _entered(sfn, execution_arn: str) -> list[str]:
    """Every state the execution history reports as entered, in the order the history lists them."""
    pages = sfn.get_paginator("get_execution_history").paginate(
        executionArn=execution_arn, reverseOrder=False
    )
    return [
        event["stateEnteredEventDetails"]["name"]
        for page in pages
        for event in page["events"]
        if event["type"].endswith("StateEntered")
    ]


def _settled(sfn, execution_arn: str, *, budget_s: float = 120.0) -> dict:
    """The execution's description once its status is terminal."""
    deadline = time.monotonic() + budget_s
    while True:
        described = sfn.describe_execution(executionArn=execution_arn)
        if described["status"] in _TERMINAL:
            return described
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the execution stayed {described['status']!r} for {budget_s}s"
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TestState walk over one definition, chaining each answer's nextState and output into the
    next call, predicts exactly the states a real execution of that definition enters and the
    output it ends with.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/test-state-isolation.html
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-sfn-walk-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_undo(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    predicted, predicted_output = _walk(sfn, role_arn, _EXECUTION_INPUT)
    assert len(predicted) >= 3, (
        f"the walk covered only {predicted!r}; the definition has four states and three on this path"
    )

    machine_name = ctx.unique_name("sim2real-behav-sfn-walk-")
    machine_arn = _once_assumable(
        lambda: sfn.create_state_machine(
            name=machine_name,
            definition=_DEFINITION,
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    )["stateMachineArn"]
    ctx.on_cleanup(_undo(lambda: sfn.delete_state_machine(stateMachineArn=machine_arn)))

    execution_arn = sfn.start_execution(
        stateMachineArn=machine_arn,
        name=ctx.unique_name("sim2real-behav-walk-"),
        input=_EXECUTION_INPUT,
    )["executionArn"]

    described = _settled(sfn, execution_arn)
    assert described["status"] == "SUCCEEDED", (
        f"the execution ended {described['status']!r}; the walk had predicted {predicted!r}"
    )

    entered = _entered(sfn, execution_arn)
    assert entered == predicted, (
        f"the execution entered {entered!r} but the TestState walk predicted {predicted!r}"
    )
    assert json.loads(described["output"]) == json.loads(predicted_output), (
        f"the execution ended with {described['output']!r}, "
        f"the walk had predicted {predicted_output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
