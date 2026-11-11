"""execution-output-numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-output-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Pass state's fixed Result containing a large integer (beyond IEEE-754 double
    precision) and a high-precision float is returned byte-identical (as parsed values)
    in DescribeExecution's output, with no rounding or type coercion."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role_for_state_machine(ctx)

    big_int = 123456789012345678901234567890  # 30 digits: far beyond float64 precision
    precise_float = 3.14159265358979311599796346854  # rounds to a specific float64 value

    definition = json.dumps(
        {
            "StartAt": "Emit",
            "States": {
                "Emit": {
                    "Type": "Pass",
                    "Result": {"bigInt": big_int, "preciseFloat": precise_float},
                    "End": True,
                }
            },
        }
    )
    sm_name = ctx.unique_name("sim2real-sfn-numeric-")
    sm_arn = _create_state_machine_with_role_propagation_retry(
        sfn, sm_name, definition, role_arn
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_name = ctx.unique_name("sim2real-sfn-numeric-exec-")
    execution_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input="{}"
    )["executionArn"]

    desc = _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc['status']}: {desc}"
    output = json.loads(desc["output"])
    assert output["bigInt"] == big_int, f"{output['bigInt']} != {big_int}"
    assert output["preciseFloat"] == precise_float, f"{output['preciseFloat']} != {precise_float}"


def _create_state_machine_with_role_propagation_retry(
    sfn, name: str, definition: str, role_arn: str, timeout_s: float = 90.0
) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)[
                "stateMachineArn"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


def _create_role_for_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    trust_policy = json.dumps(
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
    role_name = ctx.unique_name("sim2real-sfn-numrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=execution_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"execution did not terminate in {timeout_s}s, last status: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
