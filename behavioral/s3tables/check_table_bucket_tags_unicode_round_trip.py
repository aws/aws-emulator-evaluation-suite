"""table-bucket-tags-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-bucket-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values written via TagResource on a table bucket are returned
    byte-for-byte identical via ListTagsForResource, with no normalization, escaping,
    or truncation."""
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-s3t-tag-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    unicode_value = "\u6771\u4eac caf\u00e9 \u03a9 Z\u00fcrich na\u00efve r\u00e9sum\u00e9"
    unicode_key = "\u63cf\u8ff0"
    ascii_value = "plain-value-1"

    s3tables.tag_resource(resourceArn=bucket_arn, tags={unicode_key: unicode_value, "plain": ascii_value})

    got_tags = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert got_tags.get(unicode_key) == unicode_value, (
        f"unicode tag value mismatch: expected {unicode_value!r}, got {got_tags.get(unicode_key)!r}"
    )
    assert got_tags.get("plain") == ascii_value, (
        f"ascii tag value mismatch: expected {ascii_value!r}, got {got_tags.get('plain')!r}"
    )
    assert len(got_tags) == 2, f"expected exactly 2 tags, got {len(got_tags)}: {sorted(got_tags)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
