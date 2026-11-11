"""update-profile-mutates-fields-enabled-unaffected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-profile-mutates-fields-enabled-unaffected"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProfile overwrites name/duration/roleArns in place but leaves the
    enabled flag untouched (state set by Disable/EnableProfile survives an update)."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_a = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-a-')}"
    role_b = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-b-')}"
    name_a = ctx.unique_name("sim2real-ra-profile-a-")
    name_b = ctx.unique_name("sim2real-ra-profile-b-")

    profile = ra.create_profile(
        name=name_a,
        roleArns=[role_a],
        durationSeconds=1800,
        enabled=True,
    )["profile"]
    profile_id = profile["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    ra.disable_profile(profileId=profile_id)

    ra.update_profile(
        profileId=profile_id,
        name=name_b,
        durationSeconds=3600,
        roleArns=[role_b],
    )

    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["name"] == name_b, f"expected name {name_b!r} after UpdateProfile, got {got['name']!r}"
    assert got["durationSeconds"] == 3600, (
        f"expected durationSeconds 3600 after UpdateProfile, got {got['durationSeconds']!r}"
    )
    assert got["roleArns"] == [role_b], f"expected roleArns [{role_b!r}] after UpdateProfile, got {got['roleArns']!r}"
    assert got["enabled"] is False, (
        f"UpdateProfile must not touch enabled (set False by DisableProfile), got {got['enabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
