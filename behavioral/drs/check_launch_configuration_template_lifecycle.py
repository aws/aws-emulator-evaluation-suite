"""launch-configuration-template-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-configuration-template-lifecycle"
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
    """Create and Update persist the launch settings, observable through an independent
    Describe read, and Delete removes it from that same read.
    """
    drs = ctx.client("drs")

    created = drs.create_launch_configuration_template(
        copyPrivateIp=False,
        copyTags=True,
        launchDisposition="STOPPED",
        licensing={"osByol": False},
        postLaunchEnabled=False,
        targetInstanceTypeRightSizingMethod="BASIC",
        recoveryMode="OPTIMAL",
        tags={"sim2real-key": "sim2real-value"},
    )["launchConfigurationTemplate"]
    lct_id = created["launchConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_lct(drs, lct_id))
    assert created["launchDisposition"] == "STOPPED", (
        f"expected launchDisposition=STOPPED on create, got {created['launchDisposition']!r}"
    )
    assert created["recoveryMode"] == "OPTIMAL", (
        f"expected recoveryMode=OPTIMAL on create, got {created.get('recoveryMode')!r}"
    )

    updated = drs.update_launch_configuration_template(
        launchConfigurationTemplateID=lct_id,
        launchDisposition="STARTED",
        copyPrivateIp=True,
        recoveryMode="FAST",
    )["launchConfigurationTemplate"]
    assert updated["launchDisposition"] == "STARTED", (
        f"expected launchDisposition=STARTED in update response, got {updated['launchDisposition']!r}"
    )
    assert updated["recoveryMode"] == "FAST", (
        f"expected recoveryMode=FAST in update response, got {updated.get('recoveryMode')!r}"
    )
    assert updated["copyPrivateIp"] is True, (
        f"expected copyPrivateIp=True in update response, got {updated.get('copyPrivateIp')!r}"
    )

    described = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[lct_id]
    )["items"][0]
    assert described["launchDisposition"] == "STARTED", (
        f"expected launchDisposition=STARTED in independent describe read, "
        f"got {described['launchDisposition']!r}"
    )
    assert described["recoveryMode"] == "FAST", (
        f"expected recoveryMode=FAST in independent describe read, got {described.get('recoveryMode')!r}"
    )
    assert described["tags"] == {"sim2real-key": "sim2real-value"}, (
        f"expected the tags set at create to persist through describe, got {described['tags']!r}"
    )

    drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
    remaining = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[lct_id]
    )["items"]
    assert remaining == [], (
        f"the template must be gone from an independent describe read after delete, got {remaining!r}"
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
