"""choice-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-default"
GROUP = 'choice_state'
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
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
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


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Choice routes an input that matches its rule to the rule's target (output "big") and an input
    that matches no rule to Default (output "small"), so the fall-through is conditional."""
    definition = {
        "StartAt": "Choose",
        "States": {
            "Choose": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$.x",
                        "NumericGreaterThan": 100,
                        "Next": "Big",
                    },
                ],
                "Default": "Small",
            },
            "Big": {"Type": "Pass", "Result": "big", "End": True},
            "Small": {"Type": "Pass", "Result": "small", "End": True},
        },
    }
    arn = _create_state_machine(ctx, definition)

    # Control: the rule matches, so Default must NOT be taken.
    matching = _wait_execution_complete(ctx, _start_execution(ctx, arn, input_data={"x": 200}))
    assert matching["status"] == "SUCCEEDED", (
        f"control execution must succeed, got status={matching.get('status')} "
        f"error={matching.get('error')!r} cause={matching.get('cause')!r}"
    )
    assert _get_output(matching) == "big", (
        f"a matching input must route to the rule's Next, not Default; "
        f"expected output 'big', got {_get_output(matching)!r}"
    )

    # Subject: the rule does not match, so the Choice must fall through to Default.
    result = _wait_execution_complete(ctx, _start_execution(ctx, arn, input_data={"x": 5}))
    assert result["status"] == "SUCCEEDED", (
        f"execution with no matching rule must still succeed via Default, got "
        f"status={result.get('status')} error={result.get('error')!r} cause={result.get('cause')!r}"
    )
    assert _get_output(result) == "small", (
        f"expected Default fallback output 'small', got {_get_output(result)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
