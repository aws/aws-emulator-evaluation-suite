"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the specified tag keys, leaving the others intact."""
    outposts = ctx.client("outposts")
    site = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"keep-me": "yes", "remove-me": "yes"},
    )["Site"]
    site_id = site["SiteId"]
    site_arn = site["SiteArn"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    outposts.untag_resource(ResourceArn=site_arn, TagKeys=["remove-me"])

    tags = outposts.list_tags_for_resource(ResourceArn=site_arn)["Tags"]
    assert tags == {"keep-me": "yes"}, f"expected only {{'keep-me': 'yes'}} after untag, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
