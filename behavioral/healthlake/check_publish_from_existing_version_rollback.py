"""publish-from-existing-version-rollback."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "publish-from-existing-version-rollback"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishDataTransformationProfile with FromExistingVersion republishes a prior version's content as a new version."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "v1-content"}}},
        Tags={"sim2real": CHECK},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    v1 = healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")
    assert v1["Version"] == 1, f"expected first publish to be Version 1, got {v1['Version']}"

    healthlake.update_data_transformation_profile(
        ProfileId=profile_id,
        ProfileMapping={"Resources/Patient.vm": "v2-content"},
    )
    v2 = healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")
    assert v2["Version"] == 2, f"expected second publish to be Version 2, got {v2['Version']}"

    rollback = healthlake.publish_data_transformation_profile(
        ProfileId=profile_id,
        SourceFormat="CCDA",
        FromExistingVersion=1,
        ChangeDescription="rollback to v1",
    )
    assert rollback["Version"] == 3, f"expected rollback publish to be Version 3, got {rollback['Version']}"

    v3 = healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=3)
    v3_content = v3["ProfileMapping"]["Resources/Patient.vm"]
    assert v3_content == "v1-content", f"expected rollback version to republish v1's content, got {v3_content!r}"

    # v2 is untouched by the rollback publish.
    v2_reread = healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=2)
    v2_content = v2_reread["ProfileMapping"]["Resources/Patient.vm"]
    assert v2_content == "v2-content", f"expected v2 to remain untouched by the rollback publish, got {v2_content!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
