"""mitigation-action-lifecycle-and-delete-idempotency."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mitigation-action-lifecycle-and-delete-idempotency"
GROUP = "state-machine"
SERVICES = ["iot"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mitigation action is described with its type and role; after delete, Describe
    fails with ResourceNotFoundException and its exact message, a repeat delete succeeds,
    and the name can be reused."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-mitrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    group_name = ctx.unique_name("sim2real-mitgroup-")
    iot.create_thing_group(thingGroupName=group_name, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    action_name = ctx.unique_name("sim2real-mitaction-")
    action_params = {"addThingsToThingGroupParams": {"thingGroupNames": [group_name]}}
    created = iot.create_mitigation_action(
        actionName=action_name,
        roleArn=role_arn,
        actionParams=action_params,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(iot, action_name))
    assert created["actionArn"], "CreateMitigationAction response is missing actionArn"

    described = iot.describe_mitigation_action(actionName=action_name)
    assert described["actionType"] == "ADD_THINGS_TO_THING_GROUP", (
        f"expected actionType ADD_THINGS_TO_THING_GROUP, got {described['actionType']!r}"
    )
    assert described["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {described['roleArn']!r}"

    # First delete succeeds and removes the resource.
    iot.delete_mitigation_action(actionName=action_name)
    error_gone = _client_error(lambda: iot.describe_mitigation_action(actionName=action_name))
    assert error_gone.get("Code") == "ResourceNotFoundException", (
        f"describe_mitigation_action on a deleted action must raise ResourceNotFoundException, "
        f"got {error_gone.get('Code')!r}"
    )
    assert error_gone.get("Message") == f"No action with name {action_name} is found", error_gone.get("Message")

    # Deleting again (already gone) must NOT raise -- real AWS treats it as a no-op.
    try:
        iot.delete_mitigation_action(actionName=action_name)
    except ClientError as exc:
        raise AssertionError(
            f"DeleteMitigationAction on an already-deleted action must be an idempotent no-op, "
            f"but raised {exc.response['Error']['Code']!r}"
        ) from exc

    # The freed name is not merely tolerant of a repeat delete -- it is fully released, so
    # recreating under it must succeed exactly as it did the first time.
    recreated = iot.create_mitigation_action(
        actionName=action_name,
        roleArn=role_arn,
        actionParams=action_params,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    assert recreated["actionArn"], "recreating a mitigation action under its freed name must succeed"
    described_again = iot.describe_mitigation_action(actionName=action_name)
    assert described_again["actionType"] == "ADD_THINGS_TO_THING_GROUP", (
        f"expected actionType ADD_THINGS_TO_THING_GROUP after recreation, got {described_again['actionType']!r}"
    )


def _safe_delete(iot, action_name: str) -> None:
    iot.delete_mitigation_action(actionName=action_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
