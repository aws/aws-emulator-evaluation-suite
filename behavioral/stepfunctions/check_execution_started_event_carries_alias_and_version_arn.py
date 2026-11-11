"""execution-started-event-carries-alias-and-version-arn."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-started-event-carries-alias-and-version-arn"
GROUP = "execution_history"
SERVICES = ["stepfunctions"]

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


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, role_arn, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    definition = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_and_wait(ctx, sfn, sm_arn):
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return exec_arn
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within 60s: {last!r}")


def _execution_started_details(sfn, exec_arn):
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        for event in page["events"]:
            if event["type"] == "ExecutionStarted":
                return event["executionStartedEventDetails"]
    raise AssertionError(f"no ExecutionStarted event in the history of {exec_arn}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetExecutionHistory's ExecutionStarted event carries stateMachineAliasArn and
    stateMachineVersionArn when the execution was started through an alias, and carries
    neither when started through the unqualified state machine ARN."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn))

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))

    # Positive control: an unqualified-ARN execution's ExecutionStarted event carries neither field.
    unqualified_exec_arn = _start_and_wait(ctx, sfn, sm_arn)
    unqualified_details = _execution_started_details(sfn, unqualified_exec_arn)
    assert unqualified_details.get("stateMachineAliasArn") is None, (
        f"positive control: expected no stateMachineAliasArn on an unqualified-ARN execution, "
        f"got {unqualified_details!r}"
    )
    assert unqualified_details.get("stateMachineVersionArn") is None, (
        f"positive control: expected no stateMachineVersionArn on an unqualified-ARN execution, "
        f"got {unqualified_details!r}"
    )

    alias_exec_arn = _start_and_wait(ctx, sfn, alias_arn)
    alias_details = _execution_started_details(sfn, alias_exec_arn)
    assert alias_details.get("stateMachineAliasArn") == alias_arn, (
        f"expected stateMachineAliasArn == {alias_arn!r} on the ExecutionStarted event, "
        f"got {alias_details!r}"
    )
    assert alias_details.get("stateMachineVersionArn") == v1_arn, (
        f"expected stateMachineVersionArn == {v1_arn!r} on the ExecutionStarted event, "
        f"got {alias_details!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
