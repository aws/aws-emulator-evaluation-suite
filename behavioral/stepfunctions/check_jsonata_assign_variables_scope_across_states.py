"""jsonata-assign-variables-scope-across-states."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-assign-variables-scope-across-states"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
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
    """JSONata `Assign` variables stay in scope across later states even when an intervening Output
    drops the data, and are not merged into state input: Emit's `$states.input` is exactly the
    previous state's Output.
    """
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Seed",
        "States": {
            "Seed": {
                "Type": "Pass",
                "Assign": {"orderId": "{% $states.input.id %}", "factor": 3},
                "Output": {"n": "{% $states.input.n %}"},
                "Next": "Multiply",
            },
            "Multiply": {
                "Type": "Pass",
                "Assign": {"product": "{% $states.input.n * $factor %}"},
                "Output": {"passthru": True},
                "Next": "Emit",
            },
            "Emit": {
                "Type": "Pass",
                "Output": {
                    "orderId": "{% $orderId %}",
                    "product": "{% $product %}",
                    "factor": "{% $factor %}",
                    "stateInput": "{% $states.input %}",
                },
                "End": True,
            },
        },
    }
    desc = _wait_execution_complete(
        ctx,
        _start_execution(
            ctx,
            _create_state_machine(ctx, definition),
            input_data={"id": "abc", "n": 4},
        ),
        timeout_s=60,
    )
    assert desc["status"] == "SUCCEEDED", (
        f"JSONata Assign state machine did not succeed: {desc.get('status')} "
        f"error={desc.get('error')} cause={desc.get('cause')}"
    )
    output = _get_output(desc)

    # A variable assigned two states earlier is still in scope.
    assert output.get("orderId") == "abc", (
        f"$orderId assigned in Seed did not survive to Emit: got {output.get('orderId')!r} "
        f"(full output {output!r})"
    )
    # A literal (non-expression) Assign value is stored as-is and stays in scope.
    assert output.get("factor") == 3, (
        f"$factor literal Assign value wrong: got {output.get('factor')!r}"
    )
    # An expression Assign value is evaluated against BOTH the state input and an earlier variable.
    assert output.get("product") == 12, (
        f"$product should be $states.input.n(4) * $factor(3) = 12, got {output.get('product')!r}"
    )
    # Variables live in their own namespace: Emit's state input is exactly Multiply's Output.
    assert output.get("stateInput") == {"passthru": True}, (
        f"variables must NOT be merged into the state payload; Emit's $states.input should be "
        f"{{'passthru': True}} but was {output.get('stateInput')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
