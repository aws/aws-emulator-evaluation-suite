"""choice-boolean-equals."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-boolean-equals"
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
    """Choice with BooleanEquals routes correctly."""
    definition = {
        "StartAt": "Choose",
        "States": {
            "Choose": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$.enabled",
                        "BooleanEquals": True,
                        "Next": "On",
                    },
                ],
                "Default": "Off",
            },
            "On": {"Type": "Pass", "Result": "on", "End": True},
            "Off": {"Type": "Pass", "Result": "off", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, sm_arn, input_data={"enabled": True})
    result = _wait_execution_complete(ctx, exec_arn)
    got = _get_output(result)
    assert got == "on", f"enabled=True must route via BooleanEquals to On, got {got!r}"
    # Also test false case with a fresh execution on the same state machine
    exec_arn2 = _start_execution(ctx, sm_arn, input_data={"enabled": False})
    result2 = _wait_execution_complete(ctx, exec_arn2)
    got2 = _get_output(result2)
    assert got2 == "off", f"enabled=False must fail BooleanEquals:True and fall to Default, got {got2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
