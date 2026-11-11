"""error-execution-not-redrivable-on-succeeded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-execution-not-redrivable-on-succeeded"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a SUCCEEDED execution raises ExecutionNotRedrivable without side effects,
    while a FAILED twin of the same state machine is redriven successfully.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-behav-sm-redrive-")
    definition = json.dumps(
        {
            "StartAt": "Choice",
            "States": {
                "Choice": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.shouldFail", "BooleanEquals": True, "Next": "Fail"}
                    ],
                    "Default": "Succeed",
                },
                "Succeed": {"Type": "Succeed"},
                "Fail": {"Type": "Fail", "Error": "InducedFailure", "Cause": "sim2real probe"},
            },
        }
    )
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    ok_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("ok-"), input=json.dumps({"shouldFail": False})
    )["executionArn"]
    failing_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("failing-"), input=json.dumps({"shouldFail": True})
    )["executionArn"]

    ok_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=ok_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert ok_final["status"] == "SUCCEEDED", f"execution did not succeed: {ok_final['status']}"

    failing_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=failing_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert failing_final["status"] == "FAILED", f"execution did not fail: {failing_final['status']}"

    # Positive control: RedriveExecution is not blanket-refused — it succeeds on the
    # FAILED twin, and the effect is observable via an independent read.
    sfn.redrive_execution(executionArn=failing_arn)
    failing_after_redrive = sfn.describe_execution(executionArn=failing_arn)
    assert failing_after_redrive.get("redriveCount", 0) == 1, (
        f"expected redriveCount 1 after accepted redrive, got {failing_after_redrive.get('redriveCount')}"
    )

    # Negative: the same call on the SUCCEEDED execution is rejected, and rejection has
    # no side effect on the execution's recorded state.
    code, message = _refusal(lambda: sfn.redrive_execution(executionArn=ok_arn))
    assert code == "ExecutionNotRedrivable", f"expected ExecutionNotRedrivable, got {code!r}"
    expected_message = f"Execution {ok_arn} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )
    ok_after_rejected_redrive = sfn.describe_execution(executionArn=ok_arn)
    assert ok_after_rejected_redrive["status"] == "SUCCEEDED", (
        "status must remain SUCCEEDED after a rejected redrive"
    )
    assert ok_after_rejected_redrive.get("redriveCount", 0) == 0, (
        "redriveCount must not increment on a rejected redrive"
    )


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine(ctx, sfn, name, definition, role_arn):
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
