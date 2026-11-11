"""jsonata-output-and-states-input-transform."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-output-and-states-input-transform"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


# ===== helpers =====
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
# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A QueryLanguage=JSONata state machine evaluates Output and Condition expressions over
    $states.input, pinning arithmetic/string results and Choice routing in both directions.
    """
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Compute",
        "States": {
            "Compute": {
                "Type": "Pass",
                "Output": {
                    "sum": "{% $states.input.a + $states.input.b %}",
                    "label": "{% 'order-' & $states.input.id %}",
                },
                "Next": "Route",
            },
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Condition": "{% $states.input.sum > 10 %}", "Next": "Big"},
                ],
                "Default": "Small",
            },
            "Big": {
                "Type": "Pass",
                "Output": {"size": "big", "label": "{% $states.input.label %}"},
                "End": True,
            },
            "Small": {
                "Type": "Pass",
                "Output": {"size": "small", "label": "{% $states.input.label %}"},
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition)

    # sum = 12 > 10 -> Big; the label proves string concatenation with `&` ran.
    big_arn = _start_execution(ctx, sm_arn, input_data={"a": 7, "b": 5, "id": "42"})
    big = _wait_execution_complete(ctx, big_arn, timeout_s=60)
    assert big["status"] == "SUCCEEDED", (
        f"JSONata state machine did not succeed: {big.get('status')} "
        f"error={big.get('error')} cause={big.get('cause')}"
    )
    assert _get_output(big) == {"size": "big", "label": "order-42"}, (
        f"expected {{'size': 'big', 'label': 'order-42'}} from JSONata Output, "
        f"got {_get_output(big)!r} (a passthrough of the raw input means QueryLanguage was ignored)"
    )

    # sum = 3, not > 10 -> Default. Proves the JSONata Condition is really evaluated, not
    # unconditionally taken.
    small_arn = _start_execution(ctx, sm_arn, input_data={"a": 1, "b": 2, "id": "99"})
    small = _wait_execution_complete(ctx, small_arn, timeout_s=60)
    assert small["status"] == "SUCCEEDED", (
        f"JSONata Default branch did not succeed: {small.get('status')} cause={small.get('cause')}"
    )
    assert _get_output(small) == {"size": "small", "label": "order-99"}, (
        f"expected the Default branch output, got {_get_output(small)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
