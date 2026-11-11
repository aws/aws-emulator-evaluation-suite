"""list-state-machine-versions-max-results-exceeds-limit-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-state-machine-versions-max-results-exceeds-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns."""
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn, definition):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _refusal(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStateMachineVersions rejects a maxResults above the documented 1000 ceiling with
    ValidationException and the exact message, while the boundary value 1000 itself is accepted.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    definition = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, role_arn, definition)

    # Positive control: the documented ceiling itself is a valid value.
    boundary = sfn.list_state_machine_versions(stateMachineArn=sm_arn, maxResults=1000)
    assert "stateMachineVersions" in boundary, (
        f"positive control: maxResults=1000 should be accepted, got {boundary!r}"
    )

    code, message = _refusal(
        lambda: sfn.list_state_machine_versions(stateMachineArn=sm_arn, maxResults=1001)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
