"""choice-state-exited-output-and-map-choice-history-count."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-state-exited-output-and-map-choice-history-count"
GROUP = "execution_history"
SERVICES = ["stepfunctions"]


def _trust_policy() -> str:
    return json.dumps(
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


def _definition() -> str:
    return json.dumps(
        {
            "StartAt": "DoMap",
            "States": {
                "DoMap": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "Square",
                        "States": {
                            "Square": {
                                "Type": "Pass",
                                "Parameters": {"value.$": "$.value"},
                                "End": True,
                            }
                        },
                    },
                    "ResultPath": "$.mapped",
                    "Next": "Route",
                },
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.mapped[0].value",
                            "NumericGreaterThan": 0,
                            "Next": "Done",
                        }
                    ],
                    "Default": "Done",
                },
                "Done": {"Type": "Succeed"},
            },
        }
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-mapchoicehist-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-mapchoicehist-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(),
                roleArn=role_arn,
                type="STANDARD",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a)))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. Last error: {last}"
    )


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=90):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _history_events(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(
        executionArn=exec_arn, reverseOrder=False
    ):
        events.extend(page["events"])
    return events


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChoiceStateExited carries the state's output, and a Map followed by a Choice produces a
    fixed, fully-accounted history whose final event is ExecutionSucceeded with the run's output.

    Reference: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html
    """
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-mapchoicehist-ex-"),
        input=json.dumps({"items": [{"value": 1}, {"value": 2}]}),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))

    desc = _wait_execution_complete(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"the Map+Choice execution must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    events = _history_events(ctx, exec_arn)
    types = [e["type"] for e in events]
    assert types == [
        "ExecutionStarted",
        "MapStateEntered",
        "MapStateStarted",
        "MapIterationStarted",
        "MapIterationStarted",
        "PassStateEntered",
        "PassStateExited",
        "MapIterationSucceeded",
        "PassStateEntered",
        "PassStateExited",
        "MapIterationSucceeded",
        "MapStateSucceeded",
        "MapStateExited",
        "ChoiceStateEntered",
        "ChoiceStateExited",
        "SucceedStateEntered",
        "SucceedStateExited",
        "ExecutionSucceeded",
    ], (
        f"a Map over 2 items followed by a Choice must produce exactly this 18-event "
        f"history, got {len(events)} events: {types!r}"
    )

    last_event = events[-1]
    assert last_event["id"] == 18, f"ExecutionSucceeded must be event id 18, got {last_event['id']!r}"
    exec_succeeded_output = last_event.get("executionSucceededEventDetails", {}).get("output")
    assert exec_succeeded_output is not None and json.loads(exec_succeeded_output) == desc_output(desc), (
        f"ExecutionSucceeded's own output must match DescribeExecution's output; got "
        f"{exec_succeeded_output!r} vs {desc.get('output')!r}"
    )

    choice_exited = [e for e in events if e["type"] == "ChoiceStateExited"]
    assert len(choice_exited) == 1, f"expected exactly one ChoiceStateExited, got {choice_exited!r}"
    choice_details = choice_exited[0].get("stateExitedEventDetails", {})
    assert choice_details.get("name") == "Route", (
        f"ChoiceStateExited must name the state 'Route', got {choice_details!r}"
    )
    choice_output_raw = choice_details.get("output")
    assert choice_output_raw is not None, (
        f"ChoiceStateExited must carry the Choice state's output, got {choice_details!r}"
    )
    assert json.loads(choice_output_raw) == desc_output(desc), (
        f"ChoiceStateExited's output must be the Choice state's own output -- the Choice made "
        f"no change to the Map's result, so it must match the execution's final output "
        f"exactly; got {json.loads(choice_output_raw)!r} vs {desc_output(desc)!r}"
    )


def desc_output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
