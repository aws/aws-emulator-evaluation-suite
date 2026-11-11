"""tag-resource-site-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-site-roundtrip"
GROUP = "tagging"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource, merged with tags set at creation,
    and overwrites the value of a key it shares with an existing tag rather than appending a
    duplicate or leaving the old value in place."""
    outposts = ctx.client("outposts")
    site = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"created-with": "true"},
    )["Site"]
    site_id = site["SiteId"]
    site_arn = site["SiteArn"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    outposts.tag_resource(ResourceArn=site_arn, Tags={"env": "sim2real-behavioral", "owner": "checks"})

    tags = outposts.list_tags_for_resource(ResourceArn=site_arn)["Tags"]
    expected = {"created-with": "true", "env": "sim2real-behavioral", "owner": "checks"}
    assert tags == expected, f"expected exactly {expected} after TagResource, got {tags}"

    # Re-tagging an existing key must overwrite its value in place, not append a duplicate.
    outposts.tag_resource(ResourceArn=site_arn, Tags={"created-with": "false"})
    tags_after_overwrite = outposts.list_tags_for_resource(ResourceArn=site_arn)["Tags"]
    expected_after_overwrite = {"created-with": "false", "env": "sim2real-behavioral", "owner": "checks"}
    assert tags_after_overwrite == expected_after_overwrite, (
        f"expected {expected_after_overwrite} after overwriting created-with, got {tags_after_overwrite}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
