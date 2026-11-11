"""start-execution-name-idempotent-same-input."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-name-idempotent-same-input"
GROUP = 'state-machine'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecution reusing the same name+input on a Standard workflow, while that execution
    is still RUNNING, returns the same executionArn. The check holds the execution open itself."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    arn = _create_state_machine(
        ctx, role_arn, _HOLD_DEFINITION, name=ctx.unique_name("sim2real-behav-sfn-exec-idem-")
    )

    exec_name = ctx.unique_name("sim2real-behav-run-")
    r1 = sfn.start_execution(stateMachineArn=arn, name=exec_name, input="{}")
    ctx.on_cleanup(lambda: _stop_execution(sfn, r1["executionArn"]))
    held = sfn.describe_execution(executionArn=r1["executionArn"])["status"]
    assert held == "RUNNING", f"the first execution must still be open for the second call, got {held!r}"
    r2 = sfn.start_execution(stateMachineArn=arn, name=exec_name, input="{}")
    assert r1["executionArn"] == r2["executionArn"], (
        f"same name+input should be idempotent, got {r1['executionArn']!r} then {r2['executionArn']!r}"
    )
    assert r1["startDate"] == r2["startDate"], (
        f"an idempotent StartExecution must return the SAME execution's startDate, not a "
        f"newly started one: {r1['startDate']!r} vs {r2['startDate']!r}"
    )

    # Independent read at a different operation: prove only one execution actually
    # exists under this name, rather than trusting the two StartExecution responses
    # to have coincidentally echoed the same executionArn.
    executions = sfn.list_executions(stateMachineArn=arn)["executions"]
    matching = [e for e in executions if e["name"] == exec_name]
    assert len(matching) == 1, (
        f"two idempotent StartExecution calls with the same name+input must resolve to "
        f"exactly one execution, found {len(matching)} named {exec_name!r}: {matching!r}"
    )
    assert matching[0]["executionArn"] == r1["executionArn"], (
        f"the execution visible via ListExecutions must be the same one both StartExecution "
        f"calls returned, got {matching[0]['executionArn']!r} vs {r1['executionArn']!r}"
    )


# ===== helpers =====

# StartExecution is idempotent only while the named execution is open, so the definition
# holds it RUNNING in a Wait state far longer than the check takes; cleanup stops it.
_HOLD_DEFINITION = json.dumps(
    {
        "Comment": "Holds the execution open for the idempotency window",
        "StartAt": "Hold",
        "States": {"Hold": {"Type": "Wait", "Seconds": 600, "End": True}},
    }
)

_SFN_TRUST_POLICY = json.dumps(
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

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


# StopExecution is a no-op on a terminal execution; these codes mean already deleted.
_GONE_CODES = ("ExecutionDoesNotExist", "StateMachineDoesNotExist", "NoSuchEntity")


def _ignore_gone(fn):
    """Run a teardown call; only a resource that is already gone is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _create_sfn_role(ctx) -> str:
    """An execution role real Step Functions accepts on CreateStateMachine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY
    )

    def _cleanup():
        _ignore_gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _ignore_gone(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn: str, definition: str, *, name: str | None = None) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


def _stop_execution(sfn, execution_arn: str) -> None:
    """A Standard execution is a first-class resource; stop it so teardown does not
    depend on it having already completed."""
    _ignore_gone(
        lambda: sfn.stop_execution(
            executionArn=execution_arn, error="Cleanup", cause="test cleanup"
        )
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
