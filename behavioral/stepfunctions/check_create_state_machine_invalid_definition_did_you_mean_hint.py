"""create-state-machine-invalid-definition-did-you-mean-hint."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-invalid-definition-did-you-mean-hint"
GROUP = "errors"
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


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _sqs_send_definition(field_name: str) -> str:
    """A Task state calling sqs:sendMessage with one misspelled Parameters field."""
    return json.dumps(
        {
            "StartAt": "Sqs",
            "States": {
                "Sqs": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": "https://sqs.us-west-2.amazonaws.com/123456789012/q",
                        "MessageBody": "hi",
                        field_name: 5,
                    },
                    "End": True,
                }
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine's InvalidDefinition for an unsupported Parameters field names a
    'Did you mean' correction only when the field is a near miss of a real one, never for
    a field unrelated to anything Step Functions supports."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # --- Negative 1: a near-miss field name ("DelaySecond" vs "DelaySeconds") gets a hint.
    near_name = ctx.unique_name("sim2real-behav-sm-near-")
    code, message = _error(
        lambda: sfn.create_state_machine(
            name=near_name, definition=_sqs_send_definition("DelaySecond"), roleArn=role_arn,
        )
    )
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    expected_near = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: The field \"DelaySecond\" "
        "is not supported by Step Functions. Did you mean 'DelaySeconds'? at /States/Sqs/Parameters'"
    )
    assert message == expected_near, f"expected message {expected_near!r}, got {message!r}"

    # --- Negative 2: a field name unrelated to any real one gets no hint at all.
    far_name = ctx.unique_name("sim2real-behav-sm-far-")
    code, message = _error(
        lambda: sfn.create_state_machine(
            name=far_name, definition=_sqs_send_definition("XyzzyNonsenseField"), roleArn=role_arn,
        )
    )
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    expected_far = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: The field "
        "\"XyzzyNonsenseField\" is not supported by Step Functions at /States/Sqs/Parameters'"
    )
    assert message == expected_far, f"expected message {expected_far!r}, got {message!r}"
    assert "Did you mean" not in message, f"expected no hint for a far-off name, got {message!r}"

    # --- Positive control: the same shape with the correct field name succeeds.
    good_name = ctx.unique_name("sim2real-behav-sm-good-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=good_name, definition=_sqs_send_definition("DelaySeconds"), roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']!r}"

    names = [
        sm["name"]
        for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])
    ]
    assert near_name not in names, f"{near_name} should not exist after an InvalidDefinition rejection"
    assert far_name not in names, f"{far_name} should not exist after an InvalidDefinition rejection"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
