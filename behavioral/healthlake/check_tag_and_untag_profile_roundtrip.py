"""tag-and-untag-profile-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-profile-roundtrip"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a data transformation profile."""
    healthlake = ctx.client("healthlake")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-profile-")
    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    resource_arn = f"arn:aws:healthlake:{ctx.region}:{account_id}:dataTransformationProfile/{profile_id}"

    healthlake.tag_resource(ResourceARN=resource_arn, Tags=[{"Key": "sim2real-env", "Value": "test"}])

    tags_after_tag = {t["Key"]: t["Value"] for t in healthlake.list_tags_for_resource(ResourceARN=resource_arn)["Tags"]}
    assert tags_after_tag.get("sim2real-env") == "test", (
        f"expected sim2real-env=test after TagResource, got {tags_after_tag}"
    )

    healthlake.untag_resource(ResourceARN=resource_arn, TagKeys=["sim2real-env"])

    tags_after_untag = {t["Key"]: t["Value"] for t in healthlake.list_tags_for_resource(ResourceARN=resource_arn)["Tags"]}
    assert "sim2real-env" not in tags_after_untag, (
        f"expected sim2real-env removed after UntagResource, still present: {tags_after_untag}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
