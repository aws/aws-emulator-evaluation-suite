"""tag-value-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string tag value round-trips via ListResourceTags as "" (not omitted or null),
    and UntagResource then removes it."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    empty_key = ctx.unique_name("sim2real-empty-")
    other_key = ctx.unique_name("sim2real-other-")
    kms.tag_resource(
        KeyId=key_id,
        Tags=[
            {"TagKey": empty_key, "TagValue": ""},
            {"TagKey": other_key, "TagValue": "non-empty"},
        ],
    )
    ctx.on_cleanup(
        lambda: kms.untag_resource(KeyId=key_id, TagKeys=[empty_key, other_key])
    )

    tags_by_key = {
        t["TagKey"]: t["TagValue"]
        for t in kms.list_resource_tags(KeyId=key_id)["Tags"]
    }
    assert empty_key in tags_by_key, "empty-string-valued tag must not be omitted from the list"
    assert tags_by_key[empty_key] == "", "tag value must round-trip as empty string, not null/omitted"
    assert tags_by_key[other_key] == "non-empty", f"non-empty tag corrupted: {tags_by_key.get(other_key)!r}"

    kms.untag_resource(KeyId=key_id, TagKeys=[empty_key, other_key])
    remaining = {t["TagKey"] for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}
    assert empty_key not in remaining, f"UntagResource did not remove the empty-valued tag: {remaining}"
    assert other_key not in remaining, f"UntagResource did not remove the non-empty tag: {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
