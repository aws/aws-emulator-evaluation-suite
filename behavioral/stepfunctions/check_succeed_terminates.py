"""succeed-terminates."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "succeed-terminates"
GROUP = 'succeed_state'
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
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


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


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Succeed state terminates execution with SUCCEEDED status."""
    definition = {
        "StartAt": "S",
        "States": {"S": {"Type": "Succeed"}},
    }
    result = _run_to_completion(ctx, definition, {"keep": "this"})
    assert result["status"] == "SUCCEEDED", (
        f"expected execution to terminate SUCCEEDED, got {result['status']!r}"
    )
    output = _get_output(result)
    # Succeed passes through input as output
    assert output == {"keep": "this"}, (
        f"expected Succeed to pass input through unchanged as output, got {output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
