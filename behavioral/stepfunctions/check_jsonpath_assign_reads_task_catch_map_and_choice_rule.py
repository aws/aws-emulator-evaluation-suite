"""jsonpath-assign-reads-task-catch-map-and-choice-rule."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonpath-assign-reads-task-catch-map-and-choice-rule"
GROUP = 'variables'
SERVICES = ['stepfunctions']


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


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role granting only GetCallerIdentity, for the in-check Task probe."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="get-caller-identity",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:GetCallerIdentity",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="get-caller-identity"))
    )
    return arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s=60, max_attempts=6):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    desc = None
    for attempt in range(max_attempts):
        desc = _wait_execution_complete(
            ctx, _start_execution(ctx, sm_arn, input_data=input_data), timeout_s=timeout_s
        )
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in cause for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5 + attempt * 3)
    return desc


def _definition():
    return {
        "StartAt": "GetIdentity",
        "States": {
            "GetIdentity": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                "Parameters": {},
                "ResultPath": "$.identity",
                # Assign sources from the TASK RESULT: in a Task state $ is the API result.
                "Assign": {"taskVar.$": "$.Account"},
                "Next": "TryFail",
            },
            "TryFail": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "Boom",
                        "States": {
                            "Boom": {
                                "Type": "Fail",
                                "Error": "sim2real.Boom",
                                "Cause": "deliberate failure for Catch Assign",
                            },
                        },
                    },
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "ResultPath": "$.errInfo",
                        # Assign sources from the CATCH ERROR OUTPUT: $ is {Error, Cause}.
                        "Assign": {"errVar.$": "$.Error"},
                        "Next": "MapStep",
                    },
                ],
                "ResultPath": "$.parallelResult",
                "Next": "MapStep",
            },
            "MapStep": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Echo",
                    "States": {
                        "Echo": {"Type": "Pass", "End": True},
                    },
                },
                "ResultPath": "$.mapResult",
                # Assign sources from the MAP RESULT ARRAY: $ is the array of iteration outputs.
                "Assign": {"mapFirstVar.$": "$[0]"},
                "Next": "Route",
            },
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$.route",
                        "StringEquals": "first",
                        # Assign sources from the SELECTED CHOICE RULE.
                        "Assign": {"chosenVar": "from-first-rule"},
                        "Next": "Emit",
                    },
                    {
                        "Variable": "$.route",
                        "StringEquals": "second",
                        "Assign": {"chosenVar": "from-second-rule"},
                        "Next": "Emit",
                    },
                ],
                # The state-level Assign applies only on the Default path.
                "Assign": {"chosenVar": "from-default"},
                "Default": "Emit",
            },
            "Emit": {
                "Type": "Pass",
                "Parameters": {
                    "taskVar.$": "$taskVar",
                    "errVar.$": "$errVar",
                    "mapFirstVar.$": "$mapFirstVar",
                    "chosenVar.$": "$chosenVar",
                },
                "End": True,
            },
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """In JSONPath mode, `Assign` sources a variable from four distinct places: a Task's own
    result, a Catch's error output (`$.Error`), a Map's result array (`$[0]`), and the ONE Choice
    rule (or Default) actually selected -- never an unselected rule.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/workflow-variables.html
    """
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, _definition(), role_arn)

    cases = [
        ("first", "from-first-rule"),
        ("second", "from-second-rule"),
        ("other", "from-default"),
    ]
    for route, expected_chosen in cases:
        input_data = {"route": route, "items": [100, 200, 300]}
        desc = _run_to_terminal(ctx, sm_arn, input_data)
        assert desc["status"] == "SUCCEEDED", (
            f"route={route!r}: execution did not succeed: status={desc.get('status')} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        output = _get_output(desc)
        expected = {
            "taskVar": ctx.account,
            "errVar": "sim2real.Boom",
            "mapFirstVar": 100,
            "chosenVar": expected_chosen,
        }
        assert output == expected, (
            f"route={route!r}: output was {output!r}, expected {expected!r} -- taskVar must come "
            f"from GetCallerIdentity's result, errVar from the Catch's error output, mapFirstVar "
            f"from the Map's result array, and chosenVar from exactly the rule/Default selected"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
