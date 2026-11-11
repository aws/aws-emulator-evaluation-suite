"""data-transformation-profile-draft-update-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-transformation-profile-draft-update-persists"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataTransformationProfile writes new content into the mutable DRAFT (version 0)."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={
            "ProfileMapping": {
                "ProfileMapping": {"Resources/Patient.vm": "#set($x = 'initial')"}
            }
        },
        Tags={"sim2real-env": "test"},
    )
    profile_id = created["ProfileId"]
    assert created["Version"] == 0, f"expected new profile at DRAFT version 0, got {created['Version']}"
    initial_updated_at = created["LastUpdatedAt"]

    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    new_content = "#set($x = 'sim2real-marker-updated')"
    healthlake.update_data_transformation_profile(
        ProfileId=profile_id,
        ProfileMapping={"Resources/Patient.vm": new_content},
        ChangeDescription="sim2real test update",
    )

    draft = healthlake.get_data_transformation_profile(ProfileId=profile_id)
    assert draft["Version"] == 0, f"expected update to stay on DRAFT version 0, got {draft['Version']}"
    assert draft["ProfileMapping"]["Resources/Patient.vm"] == new_content, (
        f"expected updated mapping content {new_content!r}, "
        f"got {draft['ProfileMapping'].get('Resources/Patient.vm')!r}"
    )
    # timestamps carry second-level granularity; an update in the same second as
    # create is legitimate, so require non-regression rather than strict advance.
    assert draft["LastUpdatedAt"] >= initial_updated_at, (
        f"expected LastUpdatedAt to not regress after update: "
        f"initial={initial_updated_at!r}, after_update={draft['LastUpdatedAt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
