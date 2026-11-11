"""profile-logging-disabled-no-log-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "profile-logging-disabled-no-log-group"
GROUP = "state"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfile with logging DISABLED creates no CloudWatch log group, while a profile with
    logging ENABLED creates one whose name embeds its profile id."""
    b2bi = ctx.client("b2bi")
    logs = ctx.client("logs")

    control_name = ctx.unique_name("sim2real-b2bi-profile-ctrl-")
    control = b2bi.create_profile(
        name=control_name,
        phone="+15555550100",
        businessName=f"{control_name}-biz",
        logging="ENABLED",
        tags=[{"Key": "sim2real-created-with", "Value": "create-profile"}],
    )
    control_id = control["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=control_id))

    control_log_group = control.get("logGroupName")
    assert control_log_group, "positive control: logging=ENABLED must return a logGroupName"
    control_groups = logs.describe_log_groups(logGroupNamePrefix=control_log_group).get("logGroups", [])
    assert any(g["logGroupName"] == control_log_group for g in control_groups), (
        f"positive control: expected a real CloudWatch log group named {control_log_group!r}, "
        f"found {[g['logGroupName'] for g in control_groups]!r}"
    )

    prefix, sep, suffix = control_log_group.partition(control_id)
    assert sep, f"expected the control's log group name to embed its profile id, got {control_log_group!r}"

    resp = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
        tags=[{"Key": "sim2real-created-with", "Value": "create-profile"}],
    )
    profile_id = resp["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    assert not resp.get("logGroupName"), "logging=DISABLED must not return a logGroupName"

    described = b2bi.get_profile(profileId=profile_id)
    assert described["logging"] == "DISABLED", f"expected logging=DISABLED, got {described['logging']!r}"
    assert not described.get("logGroupName"), "logging=DISABLED must not have a logGroupName on GetProfile"

    would_be_log_group = f"{prefix}{profile_id}{suffix}"
    existing = logs.describe_log_groups(logGroupNamePrefix=prefix).get("logGroups", [])
    assert not any(g["logGroupName"] == would_be_log_group for g in existing), (
        f"logging=DISABLED must not create a CloudWatch log group at the destination; "
        f"found {would_be_log_group!r} among {[g['logGroupName'] for g in existing]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
