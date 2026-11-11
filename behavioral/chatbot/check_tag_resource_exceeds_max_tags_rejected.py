"""tag-resource-exceeds-max-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection at the tag cap, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tagging a custom action in batches of 10 up to 200 keys, the tag count equals what was accepted, the next
    new key fails with InvalidRequestException and no message and is not stored, a new key fits after freeing one
    slot, and changing an existing key's value at the cap succeeds."""
    chatbot = ctx.client("chatbot")
    arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo maxtags"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    # Apply tags in small batches, finding the enforced cap rather than assuming
    # the documented 200 is reachable in arbitrary batch sizes.
    batch_size = 10
    applied = 0
    hit = None
    while applied < 200:
        want = min(batch_size, 200 - applied)
        batch = [{"TagKey": f"k{i}", "TagValue": f"v{i}"} for i in range(applied, applied + want)]
        try:
            chatbot.tag_resource(ResourceARN=arn, Tags=batch)
            applied += want
        except ClientError as exc:
            hit = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            break

    assert applied > 0, "expected to be able to apply at least some tags"
    before = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert len(before) == applied, (
        f"resource tag count ({len(before)}) must match what was actually accepted "
        f"({applied}) -- a rejected batch must not be partially applied"
    )

    if hit is None:
        # All 200 were accepted: one more brand-new key must still be refused.
        hit = _error(
            lambda: chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": "k200", "TagValue": "v200"}])
        )
    code, message = hit
    # AWS's tag-cap refusal carries no message at all.
    assert (code, message) == ("InvalidRequestException", None), f"unexpected refusal {hit!r}"

    after = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert len(after) == applied, "tag count must be unchanged after the rejected call"
    assert not any(t["TagKey"] == "k200" for t in after), "rejected key k200 must not appear"

    # Restore: free exactly one slot, then the identical shape of call (one brand-new key)
    # that was just rejected then succeeds -- proving the cap is an enforced boundary,
    # not a target that has simply stopped accepting tags altogether.
    chatbot.untag_resource(ResourceARN=arn, TagKeys=["k0"])
    after_untag = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert len(after_untag) == applied - 1, (
        f"expected {applied - 1} tags after freeing one slot, got {len(after_untag)}"
    )
    assert not any(t["TagKey"] == "k0" for t in after_untag), "untagged key k0 must not reappear"

    chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": "k_restored", "TagValue": "v_restored"}])
    restored = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert restored.get("k_restored") == "v_restored", "freed-slot tag add must succeed and be visible"
    assert len(restored) == applied, "count must be back at the cap after freeing one slot and adding one"

    # Positive control: replacing the VALUE of an existing key (no growth in count) still succeeds
    # even while at the cap.
    chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": "k1", "TagValue": "updated"}])
    final = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert final["k1"] == "updated", f"expected k1 value 'updated', got {final.get('k1')!r}"
    assert len(final) == applied, f"expected count to stay at {applied}, got {len(final)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
