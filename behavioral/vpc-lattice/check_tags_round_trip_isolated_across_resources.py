"""tags-round-trip-isolated-across-resources."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-round-trip-isolated-across-resources"
GROUP = 'tag-isolation'
SERVICES = ['vpc-lattice']


def _error(fn):
    """The AWS (code, message) ``fn()`` raised; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("concern:representation", "concern:negative-classes", "axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Tags added to one service network are invisible on a sibling network, UntagResource
    removes only the named key while a second tag survives, and an untag of a key that was never
    set is a no-op rather than an error.
    """
    vl = ctx.client("vpc-lattice")

    net_a = vl.create_service_network(
        name=ctx.unique_name("sim2real-latt-taga-"), authType="NONE",
        tags={"sim2real": "vpc-lattice-tag-isolation"},
    )
    ctx.on_cleanup(lambda i=net_a["id"]: vl.delete_service_network(serviceNetworkIdentifier=i))

    net_b = vl.create_service_network(
        name=ctx.unique_name("sim2real-latt-tagb-"), authType="NONE",
        tags={"sim2real": "vpc-lattice-tag-isolation"},
    )
    ctx.on_cleanup(lambda i=net_b["id"]: vl.delete_service_network(serviceNetworkIdentifier=i))

    vl.tag_resource(resourceArn=net_a["arn"], tags={"owner": "team-a", "env": "test"})

    tags_a = vl.list_tags_for_resource(resourceArn=net_a["arn"])["tags"]
    assert tags_a.get("owner") == "team-a" and tags_a.get("env") == "test", (
        f"service network A's tags are {tags_a!r}, expected owner=team-a and env=test present"
    )

    tags_b = vl.list_tags_for_resource(resourceArn=net_b["arn"])["tags"]
    assert "owner" not in tags_b and "env" not in tags_b, (
        f"tagging network A leaked into network B's tags: {tags_b!r}"
    )
    assert tags_b.get("sim2real") == "vpc-lattice-tag-isolation", (
        f"network B's own creation-time tag went missing: {tags_b!r}"
    )

    vl.untag_resource(resourceArn=net_a["arn"], tagKeys=["owner"])
    after_untag = vl.list_tags_for_resource(resourceArn=net_a["arn"])["tags"]
    assert "owner" not in after_untag, f"owner tag survived UntagResource: {after_untag!r}"
    assert after_untag.get("env") == "test", (
        f"untagging 'owner' removed 'env' too: {after_untag!r}; UntagResource must remove only "
        f"the named key"
    )

    # Untagging a key that was never present is a no-op, not an error.
    vl.untag_resource(resourceArn=net_a["arn"], tagKeys=["never-set"])
    still_there = vl.list_tags_for_resource(resourceArn=net_a["arn"])["tags"]
    assert still_there.get("env") == "test", (
        f"a no-op UntagResource on an absent key disturbed the remaining tags: {still_there!r}"
    )

    error = _error(lambda: vl.list_tags_for_resource(resourceArn=net_a["arn"] + "-does-not-exist"))
    assert error == ("NotFoundException", "Resource was not found"), (
        f"ListTagsForResource on an ARN with no matching resource raised {error!r}, expected "
        f"('NotFoundException', 'Resource was not found')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
