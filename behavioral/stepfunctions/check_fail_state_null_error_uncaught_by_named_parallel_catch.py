"""fail-state-null-error-uncaught-by-named-parallel-catch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fail-state-null-error-uncaught-by-named-parallel-catch"
GROUP = "parallel"
SERVICES = ["stepfunctions"]


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


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_completion(ctx, role_arn, definition, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, role_arn, definition)
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _parallel_with_fail(*, fail_error, catch_error_equals):
    """A Parallel whose single branch Fails with ``fail_error``, caught only by
    ``catch_error_equals`` (never ``States.ALL``)."""
    branch_fail_state = {"Type": "Fail"}
    if fail_error is not None:
        branch_fail_state["Error"] = fail_error
    else:
        branch_fail_state["Error"] = None
    return {
        "StartAt": "P",
        "States": {
            "P": {
                "Type": "Parallel",
                "Branches": [{"StartAt": "F", "States": {"F": branch_fail_state}}],
                "Catch": [{"ErrorEquals": [catch_error_equals], "Next": "Caught"}],
                "End": True,
            },
            "Caught": {"Type": "Pass", "Result": "caught", "End": True},
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fail state's literal Error:null is accepted and fails the execution with a null
    error/cause; a Parallel Catch naming a specific ErrorEquals does not match it, while
    the same Catch does match an equal, non-null Error on an otherwise identical branch.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-fail-state.html
    """
    role_arn = _create_sfn_role(ctx)

    # Primary claim: Error:null is a valid definition, and at runtime it propagates as a
    # null error/cause that a named (non-States.ALL) Catch does not match.
    null_result = _run_to_completion(
        ctx, role_arn, _parallel_with_fail(fail_error=None, catch_error_equals="NamedError")
    )
    assert null_result["status"] == "FAILED", (
        f"a Fail state with Error:null, uncaught by a named Catch, must fail the "
        f"execution; got status={null_result['status']!r} output={_get_output(null_result)!r}"
    )
    assert null_result.get("error") is None, (
        f"an uncaught Fail with Error:null must surface a null execution error, got "
        f"{null_result.get('error')!r}"
    )
    assert null_result.get("cause") is None, (
        f"an uncaught Fail with Error:null must surface a null execution cause, got "
        f"{null_result.get('cause')!r}"
    )

    # Positive control 1: the identical Catch DOES match when the branch's Error equals
    # the Catch's ErrorEquals exactly -- the mechanism is not simply broken.
    matching_result = _run_to_completion(
        ctx, role_arn, _parallel_with_fail(fail_error="NamedError", catch_error_equals="NamedError")
    )
    assert matching_result["status"] == "SUCCEEDED", (
        f"a Catch whose ErrorEquals matches the branch's own Error must catch it; got "
        f"status={matching_result['status']!r} error={matching_result.get('error')!r}"
    )
    assert _get_output(matching_result) == "caught", (
        f"expected the matching Catch to route to the handler (output 'caught'), got "
        f"{_get_output(matching_result)!r}"
    )

    # Positive control 2: States.ALL, which matches everything including a null error,
    # DOES catch the same Error:null branch -- proving the null-error branch is a real,
    # catchable failure and not an execution that never reached the Catch machinery at all.
    all_result = _run_to_completion(
        ctx, role_arn, _parallel_with_fail(fail_error=None, catch_error_equals="States.ALL")
    )
    assert all_result["status"] == "SUCCEEDED", (
        f"States.ALL must catch a branch failing with Error:null; got "
        f"status={all_result['status']!r} error={all_result.get('error')!r}"
    )
    assert _get_output(all_result) == "caught", (
        f"expected States.ALL to route the null-error failure to the handler (output "
        f"'caught'), got {_get_output(all_result)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
