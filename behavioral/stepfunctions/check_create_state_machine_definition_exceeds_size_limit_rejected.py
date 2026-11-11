"""create-state-machine-definition-exceeds-size-limit-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-state-machine-definition-exceeds-size-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_TRUST_POLICY = json.dumps(
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

_MAX_DEFINITION_LEN = 1048576


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _unvalidated_client(ctx, service):
    """A target client with local parameter (length/range) validation disabled, so oversized
    requests are actually sent to the service instead of being rejected by botocore beforehand."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine rejects a syntactically-valid-JSON definition that exceeds the
    1,048,576-character maximum with a distinct error from one it rejects for being
    malformed JSON/ASL, and a normal-size valid definition still succeeds."""
    iam = ctx.client("iam")
    sfn_raw = _unvalidated_client(ctx, "stepfunctions")
    sfn = ctx.client("stepfunctions")

    role_name = ctx.unique_name("sim2real-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # --- Case 1: definition exceeds the max length but is otherwise well-formed JSON/ASL.
    padding = "x" * (_MAX_DEFINITION_LEN + 500)
    oversized_definition = json.dumps(
        {
            "Comment": padding,
            "StartAt": "Pass",
            "States": {"Pass": {"Type": "Pass", "End": True}},
        }
    )
    assert len(oversized_definition) > _MAX_DEFINITION_LEN, "test fixture did not actually exceed the limit"

    oversized_name = ctx.unique_name("sim2real-sfn-oversized-")
    code_oversized, message_oversized = _error(
        lambda: sfn_raw.create_state_machine(
            name=oversized_name, definition=oversized_definition, roleArn=role_arn
        )
    )
    assert code_oversized == "ValidationException", code_oversized
    assert message_oversized == (
        "1 validation error detected: Value at 'definition' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_MAX_DEFINITION_LEN}"
    ), f"unexpected ValidationException message {message_oversized!r}"
    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert oversized_name not in names, f"oversized state machine {oversized_name} exists despite rejection"

    # --- Case 2: small but syntactically malformed JSON (missing closing brace).
    malformed_name = ctx.unique_name("sim2real-sfn-malformed-")
    malformed_definition = '{"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": true}}'
    code_malformed, message_malformed = _error(
        lambda: sfn.create_state_machine(
            name=malformed_name, definition=malformed_definition, roleArn=role_arn
        )
    )
    assert code_malformed == "InvalidDefinition", code_malformed
    source = f'[Source: (String)"{malformed_definition}"'
    end = len(malformed_definition) + 1  # the 1-based column just past the last character
    assert message_malformed == (
        "Invalid State Machine Definition: 'INVALID_JSON_DESCRIPTION: Unexpected end-of-input: "
        f"expected close marker for Object (start marker at {source}; line: 1, column: 1])\n"
        f" at {source}; line: 1, column: {end}] at {source}; line: 1, column: {end}]'"
    ), f"unexpected InvalidDefinition message {message_malformed!r}"
    assert code_malformed != code_oversized, (
        f"malformed and oversized definitions must be rejected with distinct codes, both got {code_malformed}"
    )
    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert malformed_name not in names, f"malformed state machine {malformed_name} exists despite rejection"

    # --- Positive control: a normal-size, well-formed definition succeeds.
    valid_name = ctx.unique_name("sim2real-sfn-valid-")
    valid_definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    resp = sfn.create_state_machine(
        name=valid_name,
        definition=valid_definition,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=resp["stateMachineArn"]))
    desc = sfn.describe_state_machine(stateMachineArn=resp["stateMachineArn"])
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']}"
    assert desc["definition"] == valid_definition, "describe returned a different definition than was created"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
