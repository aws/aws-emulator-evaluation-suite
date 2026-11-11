"""error-validation-exception-list-versions-bad-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-validation-exception-list-versions-bad-arn"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStateMachineVersions with a non-ARN string is rejected as InvalidArn with the exact
    message: the parameter has only a length constraint, so it reaches ARN parsing. A call on a
    real state machine first proves the operation answers, so the rejection is due to the ARN."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_sfn_role(ctx)
    real_arn = _create_state_machine(ctx, role_arn)

    versions = sfn.list_state_machine_versions(stateMachineArn=real_arn)["stateMachineVersions"]
    assert versions == [], (
        f"a freshly created, never-published state machine already has versions: {versions!r}"
    )

    not_an_arn = "definitely-not-an-arn-" + ctx.unique_name("")

    code, message = _error_code(lambda: sfn.list_state_machine_versions(stateMachineArn=not_an_arn))
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}"
    expected_message = f"Invalid Arn: 'Invalid ARN prefix: {not_an_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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

_PASS_DEFINITION = json.dumps(
    {
        "Comment": "Simple pass-through state machine for behavioral checks",
        "StartAt": "PassState",
        "States": {"PassState": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting an ARN real AWS refuses is never reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    """An execution role real Step Functions accepts on CreateStateMachine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
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
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
