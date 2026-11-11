"""launch-action-lifecycle-on-launch-configuration-template."""

from __future__ import annotations
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-action-lifecycle-on-launch-configuration-template"
GROUP = "state"
SERVICES = ["drs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """PutLaunchAction attaches an action and is idempotent on the same actionId (an update, not
    a duplicate); ListLaunchActions reflects the current configuration independently, and
    DeleteLaunchAction removes it from that same read.
    """
    drs = ctx.client("drs")

    created = drs.create_launch_configuration_template(postLaunchEnabled=True)[
        "launchConfigurationTemplate"
    ]
    lct_id = created["launchConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_lct(drs, lct_id))

    action_id = str(uuid.uuid4())
    put = drs.put_launch_action(
        resourceId=lct_id,
        actionId=action_id,
        actionCode="AWS-RunShellScript",
        actionVersion="$LATEST",
        active=True,
        optional=True,
        order=2,
        name="sim2real-probe-action",
        category="CONFIGURATION",
        description="sim2real probe action",
    )
    assert put["type"] == "SSM_COMMAND", (
        f"expected PutLaunchAction to derive type=SSM_COMMAND for an SSM command document, "
        f"got {put.get('type')!r}"
    )
    assert put["order"] == 2, f"expected order=2 in the put response, got {put.get('order')!r}"

    listed = drs.list_launch_actions(resourceId=lct_id)["items"]
    assert [a["actionId"] for a in listed] == [action_id], (
        f"expected ListLaunchActions to show exactly the action just put, got {listed!r}"
    )
    assert listed[0]["order"] == 2 and listed[0]["active"] is True, (
        f"expected the listed action to carry order=2, active=True, got {listed[0]!r}"
    )

    updated = drs.put_launch_action(
        resourceId=lct_id,
        actionId=action_id,
        actionCode="AWS-RunShellScript",
        actionVersion="$LATEST",
        active=False,
        optional=True,
        order=5,
        name="sim2real-probe-action",
        category="CONFIGURATION",
        description="sim2real probe action updated",
    )
    assert updated["actionId"] == action_id, (
        "PutLaunchAction on an existing actionId must update it in place, not mint a new one, "
        f"got actionId {updated.get('actionId')!r}"
    )

    listed_after_update = drs.list_launch_actions(resourceId=lct_id)["items"]
    assert len(listed_after_update) == 1, (
        f"expected a repeated PutLaunchAction on the same actionId to still leave exactly one "
        f"action, got {listed_after_update!r}"
    )
    assert listed_after_update[0]["order"] == 5 and listed_after_update[0]["active"] is False, (
        f"expected the independent read to reflect order=5, active=False after the update, "
        f"got {listed_after_update[0]!r}"
    )

    drs.delete_launch_action(resourceId=lct_id, actionId=action_id)
    remaining = drs.list_launch_actions(resourceId=lct_id)["items"]
    assert remaining == [], (
        f"ListLaunchActions must show no actions after DeleteLaunchAction, got {remaining!r}"
    )


def _delete_lct(drs, lct_id: str) -> None:
    try:
        drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
