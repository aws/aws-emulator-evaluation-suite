"""tag-and-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-roundtrip"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges tags onto a profile; UntagResource removes only the
    specified keys, leaving the rest in place."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
        tags=[{"key": "keep-me", "value": "v0"}],
    )["profile"]
    profile_id = profile["profileId"]
    profile_arn = profile["profileArn"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    ra.tag_resource(resourceArn=profile_arn, tags=[{"key": "added-tag", "value": "v1"}])

    tags_after_tag = {t["key"]: t["value"] for t in ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]}
    assert tags_after_tag["keep-me"] == "v0", f"expected keep-me=v0 to survive TagResource, got {tags_after_tag.get('keep-me')!r}"
    assert tags_after_tag["added-tag"] == "v1", f"expected added-tag=v1 after TagResource, got {tags_after_tag.get('added-tag')!r}"

    ra.untag_resource(resourceArn=profile_arn, tagKeys=["added-tag"])

    tags_after_untag = {t["key"]: t["value"] for t in ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]}
    assert "added-tag" not in tags_after_untag, f"expected added-tag removed by UntagResource, still present: {tags_after_untag}"
    assert tags_after_untag["keep-me"] == "v0", f"expected keep-me=v0 to survive UntagResource, got {tags_after_untag.get('keep-me')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
