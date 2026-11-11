"""tag-resource-nonexistent-site-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-site-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a well-formed but nonexistent site ARN fail with NotFoundException
    and the message "Resource was not found", while the same tag on a just-created site is stored and listed.
    """
    outposts = ctx.client("outposts")
    site = outposts.create_site(Name=ctx.unique_name("sim2real-outposts-site-"))["Site"]
    site_id = site["SiteId"]
    site_arn = site["SiteArn"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    # Well-formed ARN (matches the os-[a-f0-9]{17} shape) but the site was never created.
    nonexistent_arn = site_arn.rsplit("/", 1)[0] + "/os-" + "0" * 17
    code, message = _error(
        lambda: outposts.tag_resource(ResourceArn=nonexistent_arn, Tags={"sim2real-key": "v"})
    )
    assert code == "NotFoundException", (
        f"TagResource against a well-formed but nonexistent Site ARN returned {code!r}, "
        f"expected 'NotFoundException'"
    )
    assert message == "Resource was not found", f"unexpected TagResource message: {message!r}"

    list_code, list_message = _error(
        lambda: outposts.list_tags_for_resource(ResourceArn=nonexistent_arn)
    )
    assert list_code == "NotFoundException", (
        f"ListTagsForResource against a well-formed but nonexistent Site ARN returned "
        f"{list_code!r}, expected 'NotFoundException'"
    )
    assert list_message == "Resource was not found", (
        f"unexpected ListTagsForResource message: {list_message!r}"
    )

    # Positive control: the identical Tags payload against the real Site ARN succeeds.
    outposts.tag_resource(ResourceArn=site_arn, Tags={"sim2real-key": "v"})
    tags_after = outposts.list_tags_for_resource(ResourceArn=site_arn)["Tags"]
    assert tags_after.get("sim2real-key") == "v", (
        f"the positive control TagResource against the real Site ARN did not stick: "
        f"list_tags_for_resource returned {tags_after!r}, expected 'sim2real-key': 'v'"
    )


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
