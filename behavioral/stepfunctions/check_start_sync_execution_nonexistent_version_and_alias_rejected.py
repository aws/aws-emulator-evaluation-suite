"""start-sync-execution-nonexistent-version-and-alias-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-sync-execution-nonexistent-version-and-alias-rejected"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]


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
    name = ctx.unique_name("sim2real-behav-sfnver-")
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


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution against a version number or alias name that was never published or
    created on an existing EXPRESS machine fails StateMachineDoesNotExist, naming the qualified
    ARN it was given rather than the base state machine ARN."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_express_state_machine(ctx, role_arn)

    real_version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)[
        "stateMachineVersionArn"
    ]
    real_alias_name = ctx.unique_name("sim2real-behav-alias-")
    sfn.create_state_machine_alias(
        name=real_alias_name,
        routingConfiguration=[{"stateMachineVersionArn": real_version_arn, "weight": 100}],
    )
    real_alias_arn = f"{sm_arn}:{real_alias_name}"
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=real_alias_arn))

    # Positive controls: the real version ARN and the real alias ARN both run synchronously.
    by_version = sfn.start_sync_execution(stateMachineArn=real_version_arn, input="{}")
    assert by_version["status"] == "SUCCEEDED", (
        f"positive control: the published version must run to SUCCEEDED, got {by_version['status']!r}"
    )
    by_alias = sfn.start_sync_execution(stateMachineArn=real_alias_arn, input="{}")
    assert by_alias["status"] == "SUCCEEDED", (
        f"positive control: the real alias must run to SUCCEEDED, got {by_alias['status']!r}"
    )

    # Subject: a version number that was never published on this machine.
    fake_version_arn = f"{sm_arn}:999"
    version_error = _client_error(
        lambda: sfn.start_sync_execution(stateMachineArn=fake_version_arn, input="{}")
    )
    assert version_error.get("Code") == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist for an unpublished version, got {version_error!r}"
    )
    expected_version_message = f"State Machine Does Not Exist: '{fake_version_arn}'"
    assert version_error.get("Message") == expected_version_message, (
        f"expected message {expected_version_message!r}, got {version_error.get('Message')!r}"
    )

    # Subject: an alias name that was never created on this machine.
    fake_alias_arn = f"{sm_arn}:{ctx.unique_name('no-such-alias-')}"
    alias_error = _client_error(
        lambda: sfn.start_sync_execution(stateMachineArn=fake_alias_arn, input="{}")
    )
    assert alias_error.get("Code") == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist for an uncreated alias, got {alias_error!r}"
    )
    expected_alias_message = f"State Machine Does Not Exist: '{fake_alias_arn}'"
    assert alias_error.get("Message") == expected_alias_message, (
        f"expected message {expected_alias_message!r}, got {alias_error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
