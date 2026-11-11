"""create-profile-with-tags-visible-without-tag-resource-call."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profile-with-tags-visible-without-tag-resource-call"
GROUP = "tagging"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied directly in CreateProfile's `tags` parameter are visible via
    ListTagsForResource immediately, with no separate TagResource call required -- proving
    creation-time tagging and post-hoc TagResource share the same underlying tag store."""
    b2bi = ctx.client("b2bi")

    resp = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
        tags=[{"Key": "sim2real-created-with", "Value": "create-profile"}],
    )
    profile_id = resp["profileId"]
    profile_arn = resp["profileArn"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    tags = b2bi.list_tags_for_resource(ResourceARN=profile_arn)["Tags"]
    matches = [t for t in tags if t["Key"] == "sim2real-created-with"]
    assert len(matches) == 1 and matches[0]["Value"] == "create-profile", (
        f"expected the creation-time tag to be visible without a separate TagResource call, got {tags!r}"
    )

    # A profile created WITHOUT the tags parameter must not carry it.
    untagged = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
    )
    untagged_id = untagged["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=untagged_id))
    untagged_tags = b2bi.list_tags_for_resource(ResourceARN=untagged["profileArn"])["Tags"]
    assert not any(t["Key"] == "sim2real-created-with" for t in untagged_tags), (
        f"expected no tags on a profile created without a tags parameter, got {untagged_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
