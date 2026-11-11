"""start-sync-execution-on-deleted-version-and-alias-arn-does-not-exist."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-sync-execution-on-deleted-version-and-alias-arn-does-not-exist"
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
    name = ctx.unique_name("sim2real-behav-sfndelver-")
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


def _try_delete_state_machine(sfn, arn: str) -> None:
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise


def _poll_both_until_stable_does_not_exist(
    probes, *, stable_reads=3, timeout_s=600.0, interval_s=4.0
):
    """Poll every callable in `probes` (each returning a botocore Error dict) in lockstep until
    each has reported StateMachineDoesNotExist for `stable_reads` consecutive reads in a row.

    The deletion of a qualified (version or alias) ARN is asynchronous and intermittently answers
    StateMachineDeleting in between DoesNotExist reads before settling; only the terminal, stable
    state is asserted (never a transitional one), and both ARNs are polled together so the wait is
    the max of the two settling windows rather than their sum.
    """
    deadline = time.monotonic() + timeout_s
    streaks = [0] * len(probes)
    last = [None] * len(probes)
    while time.monotonic() < deadline:
        for i, probe in enumerate(probes):
            last[i] = probe()
            if last[i] is not None and last[i].get("Code") == "StateMachineDoesNotExist":
                streaks[i] += 1
            else:
                streaks[i] = 0
        if all(s >= stable_reads for s in streaks):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"never settled on a stable StateMachineDoesNotExist within {timeout_s}s; last={last!r}"
    )


def _error_or_none(fn):
    """The botocore Error dict `fn` raises, or None on an accepted call (a valid outcome of the
    deletion race, not a violation — only the terminal, stable rejection is asserted)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return None


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Once a state machine's deletion has fully settled, StartSyncExecution through its version
    ARN or its alias ARN stably fails StateMachineDoesNotExist naming that qualified ARN."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_express_state_machine(ctx, role_arn)
    ctx.on_cleanup(lambda: _try_delete_state_machine(sfn, sm_arn))

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)[
        "stateMachineVersionArn"
    ]
    alias_name = ctx.unique_name("sim2real-behav-delalias-")
    sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )
    alias_arn = f"{sm_arn}:{alias_name}"

    # Positive controls: both qualified ARNs run synchronously while the machine is live.
    before_version = sfn.start_sync_execution(stateMachineArn=version_arn, input="{}")
    assert before_version["status"] == "SUCCEEDED", (
        f"positive control: the version ARN must run to SUCCEEDED before deletion, "
        f"got {before_version['status']!r}"
    )
    before_alias = sfn.start_sync_execution(stateMachineArn=alias_arn, input="{}")
    assert before_alias["status"] == "SUCCEEDED", (
        f"positive control: the alias ARN must run to SUCCEEDED before deletion, "
        f"got {before_alias['status']!r}"
    )

    sfn.delete_state_machine(stateMachineArn=sm_arn)

    version_error, alias_error = _poll_both_until_stable_does_not_exist(
        [
            lambda: _error_or_none(
                lambda: sfn.start_sync_execution(stateMachineArn=version_arn, input="{}")
            ),
            lambda: _error_or_none(
                lambda: sfn.start_sync_execution(stateMachineArn=alias_arn, input="{}")
            ),
        ]
    )
    expected_version_message = f"State Machine Does Not Exist: '{version_arn}'"
    assert version_error.get("Message") == expected_version_message, (
        f"expected message {expected_version_message!r}, got {version_error.get('Message')!r}"
    )
    expected_alias_message = f"State Machine Does Not Exist: '{alias_arn}'"
    assert alias_error.get("Message") == expected_alias_message, (
        f"expected message {expected_alias_message!r}, got {alias_error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
