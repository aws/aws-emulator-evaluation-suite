"""retry-backoffrate-below-one-rejected-at-create-state-machine."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-backoffrate-below-one-rejected-at-create-state-machine"
GROUP = "error_handling"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Retrier's BackoffRate below 1.0 (a shrinking delay makes no sense) is rejected
    by CreateStateMachine; the same definition with BackoffRate=1.0 still succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    valid_name = ctx.unique_name("sim2real-behav-sm-valid-")
    valid_arn = sfn.create_state_machine(
        name=valid_name, definition=_definition(ctx, 1.0), roleArn=role_arn
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=valid_arn))
    desc = sfn.describe_state_machine(stateMachineArn=valid_arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']!r}"

    invalid_name = ctx.unique_name("sim2real-behav-sm-invalid-")
    code, message = _refusal(
        lambda: sfn.create_state_machine(
            name=invalid_name, definition=_definition(ctx, 0.5), roleArn=role_arn
        )
    )
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    expected_message = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: "
        "Minimum value is 1.0 at /States/Attempt/Retry[0]/BackoffRate'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert invalid_name not in names, (
        f"{invalid_name} should not exist after an InvalidDefinition rejection"
    )


def _refusal(fn):
    """Call ``fn``; return the ``(code, message)`` it is refused with. A success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _definition(ctx, backoff_rate: float) -> str:
    resource = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:sim2real-dummy"
    return json.dumps(
        {
            "StartAt": "Attempt",
            "States": {
                "Attempt": {
                    "Type": "Task",
                    "Resource": resource,
                    "Retry": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "IntervalSeconds": 1,
                            "MaxAttempts": 1,
                            "BackoffRate": backoff_rate,
                        }
                    ],
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnretry-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Path="/sim2real/",
        Description="sim2real-behav sfn backoff validation check role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
