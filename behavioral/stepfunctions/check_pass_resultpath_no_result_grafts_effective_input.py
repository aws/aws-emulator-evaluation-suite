"""pass-resultpath-no-result-grafts-effective-input."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pass-resultpath-no-result-grafts-effective-input"
GROUP = "input_output_processing"
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

_PAYLOAD = {"nums": {"val1": 3, "val2": 4}, "outer": "untouched"}
_COMPUTED = {"val1": 3, "val2": 4, "sum": 7}


def _definition(*, with_output_path: bool) -> dict:
    """One Pass state with InputPath, Parameters and ResultPath but no Result field."""
    state = {
        "Type": "Pass",
        "InputPath": "$.nums",
        "Parameters": {
            "val1.$": "$.val1",
            "val2.$": "$.val2",
            "sum.$": "States.MathAdd($.val1, $.val2)",
        },
        "ResultPath": "$.computed",
        "End": True,
    }
    if with_output_path:
        state["OutputPath"] = "$.computed"
    return {"StartAt": "Sum", "States": {"Sum": state}}


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnnores-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnnores-sm-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied 120s after role creation: {last!r}")


def _run_to_terminal(ctx, sm_arn: str, *, timeout_s: float = 60.0) -> dict:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-x-"),
        input=json.dumps(_PAYLOAD),
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Pass state with no Result field: Parameters computes the effective input, and
    ResultPath grafts that value onto the raw execution input, ahead of OutputPath.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultpath.html
    """
    role_arn = _create_sfn_role(ctx)
    full_arn = _create_state_machine(ctx, role_arn, _definition(with_output_path=True))
    twin_arn = _create_state_machine(ctx, role_arn, _definition(with_output_path=False))

    full = _run_to_terminal(ctx, full_arn)
    assert full["status"] == "SUCCEEDED", (
        f"the full machine must SUCCEED, got {full['status']!r} error={full.get('error')!r} "
        f"cause={full.get('cause')!r}"
    )
    full_output = json.loads(full["output"])
    assert full_output == _COMPUTED, (
        "with no Result field, ResultPath must graft the Parameters-computed effective input "
        f"at $.computed, and OutputPath must then select just that node; expected {_COMPUTED!r}, "
        f"got {full_output!r}"
    )

    twin = _run_to_terminal(ctx, twin_arn)
    assert twin["status"] == "SUCCEEDED", (
        f"the no-OutputPath twin must SUCCEED, got {twin['status']!r} error={twin.get('error')!r} "
        f"cause={twin.get('cause')!r}"
    )
    twin_output = json.loads(twin["output"])
    expected_twin = {**_PAYLOAD, "computed": _COMPUTED}
    assert twin_output == expected_twin, (
        "with OutputPath removed, the merged output must be the RAW execution input "
        f"(including the 'outer' key InputPath kept away from Parameters) with the "
        f"no-Result effective value grafted at $.computed; expected {expected_twin!r}, got "
        f"{twin_output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
