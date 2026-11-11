"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = "tagging"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a real b2bi profile:
    tags attach, are visible, a targeted untag removes only the named key and leaves an
    unrelated tag in place, and a full untag leaves no tags at all."""
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-profile-")
    created = b2bi.create_profile(
        name=name, phone="+14155550100", businessName=f"{name}-biz", logging="DISABLED"
    )
    profile_id = created["profileId"]
    profile_arn = created["profileArn"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    before = b2bi.list_tags_for_resource(ResourceARN=profile_arn).get("Tags", [])
    assert before == [], f"expected no tags on a freshly created profile, found {before}"

    b2bi.tag_resource(
        ResourceARN=profile_arn,
        Tags=[
            {"Key": "Environment", "Value": "sim2real-test"},
            {"Key": "Team", "Value": "sim2real-backend"},
        ],
    )

    after_tag = {t["Key"]: t["Value"] for t in b2bi.list_tags_for_resource(ResourceARN=profile_arn)["Tags"]}
    assert after_tag.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test, got {after_tag}"
    )
    assert after_tag.get("Team") == "sim2real-backend", f"expected Team=sim2real-backend, got {after_tag}"

    b2bi.untag_resource(ResourceARN=profile_arn, TagKeys=["Environment"])

    after_partial = {
        t["Key"]: t["Value"]
        for t in b2bi.list_tags_for_resource(ResourceARN=profile_arn).get("Tags", [])
    }
    assert "Environment" not in after_partial, (
        f"Environment tag must be gone after UntagResource, still present: {after_partial}"
    )
    assert after_partial.get("Team") == "sim2real-backend", (
        f"unrelated Team tag must survive a targeted untag, got {after_partial}"
    )

    b2bi.untag_resource(ResourceARN=profile_arn, TagKeys=["Team"])

    after_full = b2bi.list_tags_for_resource(ResourceARN=profile_arn).get("Tags", [])
    assert after_full == [], f"expected no tags after untagging everything, still present: {after_full}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

