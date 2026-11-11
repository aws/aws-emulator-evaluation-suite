"""create-profile-defaults-reflect-documented-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profile-defaults-reflect-documented-values"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfile without durationSeconds defaults it to 3600 and acceptRoleSessionName and
    enabled to false, and GetProfile returns the same values CreateProfile returned.
    """
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    created = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
    )["profile"]
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    assert created["durationSeconds"] == 3600, (
        f"expected documented default durationSeconds=3600, got {created['durationSeconds']!r}"
    )
    assert created["acceptRoleSessionName"] is False, (
        f"expected documented default acceptRoleSessionName=False, got {created['acceptRoleSessionName']!r}"
    )
    assert created["enabled"] is False, (
        f"expected default enabled=False on CreateProfile, got {created['enabled']!r}"
    )

    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["durationSeconds"] == 3600, (
        f"GetProfile durationSeconds drifted from CreateProfile: expected 3600, got {got['durationSeconds']!r}"
    )
    assert got["acceptRoleSessionName"] is False, (
        f"GetProfile acceptRoleSessionName drifted from CreateProfile: expected False, got {got['acceptRoleSessionName']!r}"
    )
    assert got["enabled"] == created["enabled"], (
        f"GetProfile enabled drifted from CreateProfile: create returned {created['enabled']!r}, get returned {got['enabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
