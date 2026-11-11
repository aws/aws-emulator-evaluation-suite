"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A policy store with 50 tags refuses a 51st key with the exact TooManyTagsException and keeps 50 tags,
    still accepts a new value for an existing key, and accepts the 51st key once another key is untagged."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    arn = client.get_policy_store(policyStoreId=store_id)["arn"]

    full_tags = {f"k{i}": f"v{i}" for i in range(50)}
    client.tag_resource(resourceArn=arn, tags=full_tags)
    tags_now = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(tags_now) == 50, (
        f"expected 50 tags after filling to the limit, got {len(tags_now)}: {tags_now!r}"
    )

    error = _error(
        lambda: client.tag_resource(resourceArn=arn, tags={"k50": "v50"})
    )
    expected_error = ("TooManyTagsException", "The request exceeds the maximum number of user tags allowed")
    assert error == expected_error, (
        f"expected {expected_error!r} tagging a 51st key onto a full store, got {error!r}"
    )
    # effect absent: the 51st tag never landed.
    after_rejected = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(after_rejected) == 50, (
        f"a rejected TagResource call changed the tag count: {len(after_rejected)}, expected 50"
    )
    assert "k50" not in after_rejected, (
        f"the rejected 51st key 'k50' landed anyway: {after_rejected!r}"
    )

    # positive control: updating the value of an existing key doesn't grow
    # the tag count and is accepted.
    client.tag_resource(resourceArn=arn, tags={"k0": "updated"})
    after_update = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(after_update) == 50, (
        f"updating an existing key's value changed the tag count: {len(after_update)}, expected 50"
    )
    assert after_update["k0"] == "updated", (
        f"expected k0 updated to 'updated', got {after_update.get('k0')!r}"
    )

    # restore: freeing one slot makes the previously-rejected key acceptable,
    # pinning the refusal to the count rather than to "k50" itself.
    client.untag_resource(resourceArn=arn, tagKeys=["k1"])
    client.tag_resource(resourceArn=arn, tags={"k50": "v50"})
    after_restore = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_restore.get("k50") == "v50", (
        f"k50 did not land once a slot was freed: {after_restore!r}"
    )
    assert "k1" not in after_restore, (
        f"expected k1 removed by untag_resource, still present: {after_restore!r}"
    )
    assert len(after_restore) == 50, (
        f"expected exactly 50 tags after freeing one slot and adding k50, got {len(after_restore)}: "
        f"{after_restore!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
