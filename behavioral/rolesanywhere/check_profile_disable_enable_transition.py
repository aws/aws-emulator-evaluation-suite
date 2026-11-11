"""profile-disable-enable-transition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "profile-disable-enable-transition"
GROUP = "state"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableProfile/EnableProfile flip profile.enabled and GetProfile reflects each transition."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    created = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
        enabled=True,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["profile"]
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: _delete_profile_ignore_missing(ra, profile_id))

    assert created["enabled"] is True

    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["enabled"] is True

    disabled = ra.disable_profile(profileId=profile_id)["profile"]
    assert disabled["enabled"] is False
    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["enabled"] is False

    enabled = ra.enable_profile(profileId=profile_id)["profile"]
    assert enabled["enabled"] is True
    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["enabled"] is True


def _delete_profile_ignore_missing(ra, profile_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ra.delete_profile(profileId=profile_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
