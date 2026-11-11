"""start-execution-returns-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-returns-arn"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machines here call no AWS API on the customer's behalf, so the role carries no
    permissions. It is created rather than looked up because a role the check did not create
    is account configuration, not a service contract.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying the one error IAM propagation can produce.

    A freshly created role is not instantly assumable and IAM exposes no condition to poll
    for that, so the bounded AccessDeniedException retry is the wait.
    """
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecution's returned executionArn is independently discoverable and correctly identified."""
    sfn = ctx.client("stepfunctions")
    definition = {
        "StartAt": "Pass",
        "States": {"Pass": {"Type": "Pass", "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_name = ctx.unique_name("sim2real-behav-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=exec_name, input="{}")
    ctx.on_cleanup(lambda a=resp["executionArn"]: sfn.stop_execution(executionArn=a))
    assert "executionArn" in resp, f"StartExecution response missing executionArn: {resp!r}"
    assert "startDate" in resp, f"StartExecution response missing startDate: {resp!r}"
    exec_arn = resp["executionArn"]
    sm_name = sm_arn.split(":")[-1]
    assert ":execution:" in exec_arn, f"Expected ':execution:' in ARN: {exec_arn}"
    assert sm_name in exec_arn, f"Expected SM name '{sm_name}' in execution ARN: {exec_arn}"

    described = sfn.describe_execution(executionArn=exec_arn)
    assert described["stateMachineArn"] == sm_arn, (
        f"DescribeExecution (independent read) stateMachineArn {described['stateMachineArn']!r} "
        f"!= the state machine StartExecution was called against {sm_arn!r}"
    )
    assert described["name"] == exec_name, (
        f"DescribeExecution (independent read) name {described['name']!r} != requested {exec_name!r}"
    )

    listed_arns = {
        e["executionArn"] for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    }
    assert exec_arn in listed_arns, (
        f"Started execution {exec_arn} not visible via independent ListExecutions: {listed_arns!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
