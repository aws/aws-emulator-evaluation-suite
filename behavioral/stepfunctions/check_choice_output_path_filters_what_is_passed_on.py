"""choice-output-path-filters-what-is-passed-on."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-output-path-filters-what-is-passed-on"
GROUP = "choice_state"
SERVICES = ["stepfunctions"]


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
            return desc
        time.sleep(0.5)
    raise AssertionError(
        f"execution for input {input_data!r} never reached a terminal status within "
        f"{timeout_s}s; last describe was {desc!r}"
    )


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


def _machine(*, with_output_path):
    """A Choice routed by the InputPath-filtered input; the downstream Pass echoes its own input
    back verbatim, so what it receives is observable at the top level."""
    route = {
        "Type": "Choice",
        "InputPath": "$.inner",
        "Choices": [{"Variable": "$.v", "NumericGreaterThan": 10, "Next": "Next"}],
        "Default": "Next",
    }
    if with_output_path:
        route["OutputPath"] = "$.keep"
    return {
        "StartAt": "Route",
        "States": {
            "Route": route,
            "Next": {"Type": "Pass", "Parameters": {"got.$": "$"}, "End": True},
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Choice state's OutputPath filters what the SELECTED branch passes downstream: it applies
    to the (InputPath-filtered) effective input the branch left unchanged, after routing.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-outputpath.html
    """
    role_arn = _execution_role(ctx)
    input_data = {"inner": {"v": 50, "keep": "secret"}, "outer": "junk"}

    filtered_arn = _create_state_machine(ctx, _machine(with_output_path=True), role_arn)
    desc = _run_execution(ctx, filtered_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"the OutputPath machine must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert _output(desc) == {"got": "secret"}, (
        f"the Choice's OutputPath '$.keep' must select the 'keep' field of the InputPath-filtered "
        f"document ({{'v': 50, 'keep': 'secret'}}) before handing it to 'Next'; expected "
        f"{{'got': 'secret'}}, got {_output(desc)!r}"
    )

    # Control: the same input and routing decision, without OutputPath, passes the whole
    # InputPath-filtered document on -- so the field drop above is attributable to OutputPath.
    unfiltered_arn = _create_state_machine(ctx, _machine(with_output_path=False), role_arn)
    control = _run_execution(ctx, unfiltered_arn, input_data)
    assert control["status"] == "SUCCEEDED", (
        f"the no-OutputPath control must succeed, got status={control.get('status')} "
        f"error={control.get('error')!r} cause={control.get('cause')!r}"
    )
    assert _output(control) == {"got": {"v": 50, "keep": "secret"}}, (
        f"without OutputPath, 'Next' must receive the whole InputPath-filtered document; "
        f"expected {{'got': {{'v': 50, 'keep': 'secret'}}}}, got {_output(control)!r} -- this is "
        f"what makes the filtered machine's narrower output attributable to OutputPath, not to "
        f"the input or the routing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
