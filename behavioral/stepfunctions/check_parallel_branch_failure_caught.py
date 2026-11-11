"""parallel-branch-failure-caught."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parallel-branch-failure-caught"
GROUP = 'parallel_state'
SERVICES = ['stepfunctions']

def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
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
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
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


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

def _definition(*, second_branch_fails: bool):
    second_branch_state = (
        {
            "Type": "Fail",
            "Error": "BranchFailed",
            "Cause": "intentional",
        }
        if second_branch_fails
        else {"Type": "Pass", "Result": "also-fine", "End": True}
    )
    return {
        "StartAt": "P",
        "States": {
            "P": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "OK",
                        "States": {"OK": {"Type": "Pass", "Result": "fine", "End": True}},
                    },
                    {
                        "StartAt": "Bad",
                        "States": {"Bad": second_branch_state},
                    },
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "ResultPath": "$.error",
                        "Next": "HandleError",
                    }
                ],
                "Next": "Done",
            },
            "HandleError": {
                "Type": "Pass",
                "Result": "caught",
                "End": True,
            },
            "Done": {"Type": "Pass", "Result": "no-error", "End": True},
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Parallel whose branch fails is caught and routed to its handler (output "caught"), while the same
    Parallel with no failing branch completes normally (output "no-error")."""
    result = _run_to_completion(ctx, _definition(second_branch_fails=True), {})
    assert result["status"] == "SUCCEEDED", (
        f"the Parallel must still complete the execution successfully via Catch when a branch "
        f"fails, got status={result['status']!r} error={result.get('error')!r} "
        f"cause={result.get('cause')!r}"
    )
    assert _get_output(result) == "caught", (
        f"a failing branch must route through Catch to HandleError (output 'caught'), "
        f"got {_get_output(result)!r}"
    )

    control = _run_to_completion(ctx, _definition(second_branch_fails=False), {})
    assert control["status"] == "SUCCEEDED", (
        f"the control execution (no failing branch) must succeed, got "
        f"status={control['status']!r} error={control.get('error')!r} "
        f"cause={control.get('cause')!r}"
    )
    assert _get_output(control) == "no-error", (
        f"when no branch fails the Parallel must skip the Catch and reach Done (output "
        f"'no-error'), got {_get_output(control)!r} -- a target that always routes to the "
        f"Catch handler would wrongly produce 'caught' here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
