"""succeed-input-path-output-path-filters."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "succeed-input-path-output-path-filters"
GROUP = 'succeed_state'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machine here calls no AWS API on the customer's behalf, so the role carries no
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """CreateStateMachine, retrying the one error IAM propagation can produce."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_to_completion(ctx, sm_arn, input_data, *, timeout_s=60.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Succeed state's InputPath selects what it receives and OutputPath selects what
    becomes the execution output, same as any other state's filter pair.
    """
    role_arn = _create_sfn_role(ctx)
    definition = {
        "StartAt": "S",
        "States": {
            "S": {
                "Type": "Succeed",
                "InputPath": "$.keep",
                "OutputPath": "$.inner",
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    result = _run_to_completion(ctx, sm_arn, {"keep": {"inner": 42, "other": "x"}, "drop": "y"})
    assert result["status"] == "SUCCEEDED", (
        f"expected execution to terminate SUCCEEDED, got {result['status']!r} "
        f"error={result.get('error')!r} cause={result.get('cause')!r}"
    )
    output = _get_output(result)
    assert output == 42, (
        f"InputPath '$.keep' then OutputPath '$.inner' on a Succeed state must yield 42, "
        f"got {output!r}"
    )

    # Positive control: a different input proves the value is read through the paths, not fixed.
    result2 = _run_to_completion(ctx, sm_arn, {"keep": {"inner": 99, "other": "z"}, "drop": "w"})
    assert result2["status"] == "SUCCEEDED", (
        f"expected execution to terminate SUCCEEDED, got {result2['status']!r}"
    )
    output2 = _get_output(result2)
    assert output2 == 99, (
        f"a second execution with inner=99 must yield 99 through the same filter pair, "
        f"got {output2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
