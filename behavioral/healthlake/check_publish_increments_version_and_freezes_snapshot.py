"""publish-increments-version-and-freezes-snapshot."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "publish-increments-version-and-freezes-snapshot"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Publishing freezes an immutable numbered version; later draft edits never mutate it."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "v1-content"}}},
        Tags={"sim2real-env": "test"},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    pub1 = healthlake.publish_data_transformation_profile(
        ProfileId=profile_id, SourceFormat="CCDA", ChangeDescription="v1"
    )
    assert pub1["Version"] == 1, f"expected first publish to allocate version 1, got {pub1['Version']}"

    healthlake.update_data_transformation_profile(
        ProfileId=profile_id,
        ProfileMapping={"Resources/Patient.vm": "v2-content"},
    )

    pub2 = healthlake.publish_data_transformation_profile(
        ProfileId=profile_id, SourceFormat="CCDA", ChangeDescription="v2"
    )
    assert pub2["Version"] == 2, f"expected second publish to increment to version 2, got {pub2['Version']}"

    # v1's frozen snapshot must still hold the content that was drafted at publish time,
    # untouched by the later draft edit to v2-content.
    version1 = healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=1)
    got_v1 = version1["ProfileMapping"]["Resources/Patient.vm"]
    assert got_v1 == "v1-content", f"expected frozen version 1 to still hold 'v1-content', got {got_v1!r}"

    version2 = healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=2)
    got_v2 = version2["ProfileMapping"]["Resources/Patient.vm"]
    assert got_v2 == "v2-content", f"expected version 2 to hold 'v2-content', got {got_v2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
