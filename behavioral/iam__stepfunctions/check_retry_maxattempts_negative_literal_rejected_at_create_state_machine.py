"""retry-maxattempts-negative-literal-rejected-at-create-state-machine."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-maxattempts-negative-literal-rejected-at-create-state-machine"
GROUP = "error_handling"
SERVICES = ["iam", "stepfunctions"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _error(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected CreateStateMachine to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine rejects a Retry whose MaxAttempts is negative with AWS's own
    schema-validation error — the field is never silently clamped to 0 or ignored."""
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)

    name = ctx.unique_name("sim2real-behav-sfnmaxneg-")
    code, message = _error(lambda: _create_once_role_assumable(
        ctx, name, _definition(activity_arn), role_arn
    ))
    assert code == "InvalidDefinition", (
        f"a Retry with a negative MaxAttempts must be refused with InvalidDefinition; "
        f"got code={code!r} message={message!r}"
    )
    expected_message = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Minimum value is 0 at "
        "/States/Attempt/Retry[0]/MaxAttempts'"
    )
    assert message == expected_message, (
        f"expected the schema-validation message {expected_message!r}; got {message!r}"
    )

    # Positive control: the same definition with a non-negative MaxAttempts is accepted.
    good_name = ctx.unique_name("sim2real-behav-sfnmaxneg-ctrl-")
    good_arn = _create_once_role_assumable(
        ctx, good_name, _definition(activity_arn, max_attempts=0), role_arn
    )["stateMachineArn"]
    sfn = ctx.client("stepfunctions")
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=good_arn),
                              "StateMachineDoesNotExist"))
    desc = sfn.describe_state_machine(stateMachineArn=good_arn)
    assert desc["status"] == "ACTIVE", (
        f"the positive control (MaxAttempts=0) must be accepted and ACTIVE; got {desc['status']!r}"
    )


def _definition(activity_arn: str, *, max_attempts: int = -1) -> str:
    return json.dumps({
        "StartAt": "Attempt",
        "States": {
            "Attempt": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": 30,
                "Retry": [{
                    "ErrorEquals": ["States.ALL"],
                    "IntervalSeconds": 1,
                    "MaxAttempts": max_attempts,
                }],
                "End": True,
            }
        },
    })


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmaxneg-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnmaxneg-act-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=arn),
                              "ActivityDoesNotExist"))
    return arn


def _create_once_role_assumable(ctx, name: str, definition: str, role_arn: str) -> dict:
    """CreateStateMachine, retrying only the AccessDeniedException a fresh role's trust has not
    yet propagated past. A non-AccessDenied ClientError (the behavior under test) propagates."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after role creation; last error {last!r}"
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
