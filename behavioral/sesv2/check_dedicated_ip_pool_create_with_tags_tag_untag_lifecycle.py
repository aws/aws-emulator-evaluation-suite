"""dedicated-ip-pool-create-with-tags-tag-untag-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "dedicated-ip-pool-create-with-tags-tag-untag-lifecycle"
GROUP = "dedicated-ips"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDedicatedIpPool's inline Tags are visible via ListTagsForResource, and
    TagResource/UntagResource then add and remove tags on the same pool.
    """
    sesv2 = ctx.client("sesv2")

    pool_name = ctx.unique_name("sim2real-dip-pool-")
    sesv2.create_dedicated_ip_pool(PoolName=pool_name, Tags=[{"Key": "env", "Value": "dev"}])
    ctx.on_cleanup(lambda: sesv2.delete_dedicated_ip_pool(PoolName=pool_name))
    resource_arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:dedicated-ip-pool/{pool_name}"

    listed = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert listed == [{"Key": "env", "Value": "dev"}], (
        f"expected the pool's inline creation tag to be visible, got {listed!r}"
    )

    sesv2.tag_resource(ResourceArn=resource_arn, Tags=[{"Key": "owner", "Value": "alice"}])
    after_tag = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    expected_after_tag = [{"Key": "env", "Value": "dev"}, {"Key": "owner", "Value": "alice"}]
    assert sorted(after_tag, key=lambda t: t["Key"]) == expected_after_tag, (
        f"expected tags {expected_after_tag!r} after TagResource, got {after_tag!r}"
    )

    sesv2.untag_resource(ResourceArn=resource_arn, TagKeys=["env"])
    after_untag = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert after_untag == [{"Key": "owner", "Value": "alice"}], (
        f"expected only the 'owner' tag to remain after UntagResource, got {after_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
