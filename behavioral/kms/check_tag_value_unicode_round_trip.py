"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value with accented Latin, CJK and German characters round-trips byte-identical
    through TagResource and ListResourceTags."""
    kms = ctx.client("kms")
    key_id = kms.create_key(Description=ctx.unique_name("sim2real-kms-tagunicode-"))["KeyMetadata"][
        "KeyId"
    ]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    tag_key = "sim2real-unicode-tag"
    # KMS rejects emoji/symbol characters in tag values with TagException.
    tag_value = "caf\u00e9-\u65e5\u672c\u8a9e-\u00df\u00f1-\u4e2d\u6587"  # café, Japanese, ß, ñ, Chinese
    kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": tag_key, "TagValue": tag_value}])

    tags = kms.list_resource_tags(KeyId=key_id)["Tags"]
    matches = [t for t in tags if t["TagKey"] == tag_key]
    assert len(matches) == 1, f"expected exactly one matching tag, got {matches}"
    assert matches[0]["TagValue"] == tag_value, f"{matches[0]['TagValue']!r} != {tag_value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
