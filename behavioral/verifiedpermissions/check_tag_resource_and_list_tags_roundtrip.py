"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "control-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied to a policy store via TagResource are visible through
    ListTagsForResource, and UntagResource removes exactly the requested key
    while leaving the others intact."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    arn = client.get_policy_store(policyStoreId=store_id)["arn"]

    client.tag_resource(resourceArn=arn, tags={"env": "test", "owner": "sim2real"})
    tags = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "test", "owner": "sim2real"}, (
        f"expected {{'env': 'test', 'owner': 'sim2real'}} from an independent "
        f"ListTagsForResource after TagResource, got {tags!r}"
    )

    client.untag_resource(resourceArn=arn, tagKeys=["env"])
    tags_after = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {"owner": "sim2real"}, (
        f"expected only {{'owner': 'sim2real'}} to remain after "
        f"UntagResource(tagKeys=['env']), got {tags_after!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
