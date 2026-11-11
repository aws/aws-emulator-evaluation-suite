"""test-state-task-unassumable-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-task-unassumable-role"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]

_WRONG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_RIGHT_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_TASK_DEFINITION = json.dumps(
    {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:sfn:listStateMachines",
        "Parameters": {},
        "Retry": [{"ErrorEquals": ["States.ALL"], "IntervalSeconds": 2, "MaxAttempts": 2, "BackoffRate": 2}],
        "End": True,
    }
)

_TASK_WITH_CATCH_DEFINITION = json.dumps(
    {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:sfn:listStateMachines",
        "Parameters": {},
        "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "Handle"}],
        "End": True,
    }
)

_PLAIN_TASK_DEFINITION = json.dumps(
    {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:sfn:listStateMachines", "Parameters": {}, "End": True}
)


_LIST_STATE_MACHINES_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "states:ListStateMachines", "Resource": "*"}]}
)


def _create_role(ctx, trust_policy: str, inline_policy: str | None = None) -> str:
    """An IAM role with the given trust policy; deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    if inline_policy is not None:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=inline_policy)
    return role_arn


def _not_assume_error(role_arn: str) -> str:
    return f"The principal states.amazonaws.com is not authorized to assume the provided role. (role: {role_arn})"


def _await_assumable(fn, role_arn: str, *, timeout_s=90.0):
    """Call fn(), retrying while the new role's trust policy has not yet propagated.

    An AccessDeniedException from the API itself, and a 200 whose simulated status is FAILED
    with the not-authorized-to-assume cause, are both signs of the same unsettled trust policy.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
            continue
        if result.get("status") == "FAILED" and result.get("cause") == _not_assume_error(role_arn):
            if time.monotonic() > deadline:
                return result
            time.sleep(5)
            continue
        return result


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState on a Task whose roleArn cannot be assumed fails States.TaskFailed with the
    exact assume-role message and no nextState; a matching Retry reports RETRIABLE plus
    errorDetails, a matching Catch reports CAUGHT_ERROR plus catchIndex and nextState."""
    sfn = ctx.client("stepfunctions")
    bad_role_arn = _create_role(ctx, _WRONG_TRUST_POLICY)
    good_role_arn = _create_role(ctx, _RIGHT_TRUST_POLICY, _LIST_STATE_MACHINES_POLICY)

    # Positive control: the identical Task definition with a role states.amazonaws.com CAN
    # assume, and that carries permission for the call, succeeds -- proving the failures below
    # are about assumability, not the definition.
    control = _await_assumable(
        lambda: sfn.test_state(
            definition=_PLAIN_TASK_DEFINITION, roleArn=good_role_arn, input="{}", inspectionLevel="DEBUG"
        ),
        good_role_arn,
    )
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"

    plain = sfn.test_state(
        definition=_PLAIN_TASK_DEFINITION, roleArn=bad_role_arn, input="{}", inspectionLevel="DEBUG"
    )
    assert plain["status"] == "FAILED", f"expected FAILED, got {plain!r}"
    assert plain["error"] == "States.TaskFailed", f"expected States.TaskFailed, got {plain!r}"
    assert plain["cause"] == _not_assume_error(bad_role_arn), f"unexpected cause: {plain!r}"
    assert plain.get("nextState") is None, f"FAILED must not return nextState: {plain!r}"

    retriable = sfn.test_state(
        definition=_TASK_DEFINITION, roleArn=bad_role_arn, input="{}", inspectionLevel="DEBUG"
    )
    assert retriable["status"] == "RETRIABLE", f"expected RETRIABLE, got {retriable!r}"
    assert retriable["error"] == "States.TaskFailed", f"expected States.TaskFailed, got {retriable!r}"
    assert retriable["cause"] == _not_assume_error(bad_role_arn), f"unexpected cause: {retriable!r}"
    assert retriable.get("nextState") is None, f"RETRIABLE must not return nextState: {retriable!r}"
    details = retriable["inspectionData"]["errorDetails"]
    assert details["retryIndex"] == 0, f"expected retryIndex 0, got {details!r}"
    assert details["retryBackoffIntervalSeconds"] == 2, f"expected backoff 2, got {details!r}"

    caught = sfn.test_state(
        definition=_TASK_WITH_CATCH_DEFINITION, roleArn=bad_role_arn, input="{}", inspectionLevel="DEBUG"
    )
    assert caught["status"] == "CAUGHT_ERROR", f"expected CAUGHT_ERROR, got {caught!r}"
    assert caught["nextState"] == "Handle", f"expected nextState Handle, got {caught!r}"
    caught_details = caught["inspectionData"]["errorDetails"]
    assert caught_details["catchIndex"] == 0, f"expected catchIndex 0, got {caught_details!r}"
    output = json.loads(caught["output"])
    assert output == {"Error": "States.TaskFailed", "Cause": _not_assume_error(bad_role_arn)}, (
        f"unexpected CAUGHT_ERROR output: {caught!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
