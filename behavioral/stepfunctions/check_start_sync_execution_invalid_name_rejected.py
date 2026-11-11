"""start-sync-execution-invalid-name-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-sync-execution-invalid-name-rejected"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]
_BAD_NAME = "bad:name:with:colons"


def _trust_policy() -> str:
    return json.dumps(
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


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_express_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnsync-")
    definition = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartSyncExecution with a name containing a colon (banned by the API's name constraints)
    fails InvalidName; a valid name on the same EXPRESS machine still runs synchronously."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_express_state_machine(ctx, role_arn)

    good_name = ctx.unique_name("exec-good-")
    good = sfn.start_sync_execution(stateMachineArn=sm_arn, name=good_name, input="{}")
    assert good["status"] == "SUCCEEDED", (
        f"positive control: a valid name must run to SUCCEEDED, got {good['status']!r}"
    )
    assert good["name"] == good_name, (
        f"expected name {good_name!r} echoed back, got {good['name']!r}"
    )

    error = _client_error(
        lambda: sfn.start_sync_execution(stateMachineArn=sm_arn, name=_BAD_NAME, input="{}")
    )
    assert error.get("Code") == "InvalidName", f"expected InvalidName, got {error!r}"
    expected_message = f"Invalid Name: '{_BAD_NAME}'"
    assert error.get("Message") == expected_message, (
        f"expected InvalidName message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
